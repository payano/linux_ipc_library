/*
MIT License
Copyright (c) 2020 Johan Svensson
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "ipc_com.h"
#include <fcntl.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <semaphore.h>
#include <stdint.h>

#define MAX_NAME_LEN 50
#define OPEN_META_RETRIES 30
#define SHM_CREATE_OFLAGS (O_CREAT | O_EXCL |O_RDWR)
#define SHM_READ_OFLAGS (O_RDWR)
#define SHM_MODE (S_IRUSR | S_IWUSR)
#define MMAP_PROT (PROT_READ | PROT_WRITE)
#define MMAP_FLAGS (MAP_SHARED)

#ifdef DEBUG
#define log_debug(...) printf(__VA_ARGS__)
#else
#define log_debug(...)
#endif

struct ipc_occupied {
	int allocated;
	int sz;
};

struct ipc_fd_queue {
	int fd_payload;
	int fd_occupied;
	int fd_locking;
	int fd_queue_meta;
};

struct ipc_fds {
	struct ipc_fd_queue write;
	struct ipc_fd_queue read;
	int fd_queue_meta;
};

struct ipc_queue_locking
{
	sem_t sem_empty;
	sem_t sem_full;
	pthread_mutex_t mutex_lock;
};

struct ipc_queue_meta_queue
{
	char file_payload[MAX_NAME_LEN+15];
	char file_occupied[MAX_NAME_LEN+15];
	char file_locking[MAX_NAME_LEN+15];
};

struct ipc_queue_meta
{
	char file_queue_meta_read[MAX_NAME_LEN+15];
	char file_queue_meta_write[MAX_NAME_LEN+15];

	struct ipc_queue_meta_queue meta_server_read;
	struct ipc_queue_meta_queue meta_server_write;

	int queue_total_sz;
	int queue_item_sz;
	int queue_cnt;

	int initialized;
};

struct ipc_queue_data
{
	struct ipc_queue_locking *shm_locking; /* shm */
	struct ipc_occupied  *shm_occupied;  /* shm */
	void *shm_payload; /* shm */
	int setup_finished; /* 1 = OK*/
};

struct ipc_data
{
	struct ipc_fds fds;
	char file_shm[MAX_NAME_LEN];
	char file_queue_meta[MAX_NAME_LEN+15];

	struct ipc_queue_meta *metadata; /* shm */
	struct ipc_queue_data read;
	struct ipc_queue_data write;
	enum NODE_TYPE type;

	int payload_sz;
	int queue_cnt;
	int total_sz;

	callback cb;
	pthread_t run_thread;

	int run;

};

static int create_shm(int *fd, char *filename, void **set_addr, int sz)
{
	int ret;
	*fd = shm_open(filename, SHM_CREATE_OFLAGS, SHM_MODE);
	if(*fd < 0) {
		perror("could not shm_open");
		return -1;
	}

	ret = ftruncate(*fd,sz);
	if(ret) {
		perror("could not shm_open");
		goto error;
	}

	*set_addr = mmap(NULL, sz, MMAP_PROT, MMAP_FLAGS, *fd, 0);
	return ret;

error:
	close(*fd);
	return ret;
}

static int open_shm(int *fd, char *filename, void **set_addr, int sz)
{
	*fd = shm_open(filename, SHM_READ_OFLAGS, SHM_MODE);
	if(*fd < 0) {
		perror("could not shm_open");
		return -1;
	}

	*set_addr = mmap(NULL, sz, MMAP_PROT, MMAP_FLAGS, *fd, 0);
	return 0;
}

static void *thread_main(void *arg)
{
	struct ipc_data *data = arg;
	struct timespec ts;
	int ret;
	struct ipc_occupied *occupied_ptr;

	/* here we wait */
	while(data->run) {
		if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
			return NULL;
		ts.tv_sec += 2;

		log_debug("main() about to call sem_timedwait()\n");
		while ((ret = sem_timedwait(&data->read.shm_locking->sem_empty, &ts)) == -1
				&& errno == EINTR)
			continue;	/* Restart if interrupted by handler */

		/* Check what happened */
		if (ret == -1) {
			if (errno == ETIMEDOUT) {
				log_debug("sem_timedwait() timed out\n");
				continue;
			} else {
				perror("sem_timedwait");
				return NULL;
			}
		}

		log_debug("sem_timedwait() succeeded\n");

		/* do stuff */
		pthread_mutex_lock(&data->read.shm_locking->mutex_lock);

		log_debug("FINDING ITEM\n");
		occupied_ptr = data->read.shm_occupied;
		uint8_t *shm_payload = data->read.shm_payload;
		for(int i = 0; i < data->queue_cnt; ++i) {
			if(1 == occupied_ptr->allocated) {
				/* item */
				log_debug("CALLING CALLBACK\n");
				data->cb(shm_payload, occupied_ptr->sz);
				occupied_ptr->allocated = 0;
				occupied_ptr->sz = 0;
				if (sem_post(&data->read.shm_locking->sem_full) == -1)
					perror("Error with sem_post");
			}
			shm_payload += data->payload_sz;
		}

		pthread_mutex_unlock(&data->read.shm_locking->mutex_lock);
		/* end */

	}

	return NULL;
}

static int init_locking(struct ipc_data *data, struct ipc_queue_locking *lock)
{
	int ret;
	int shared = 1;

	ret = sem_init(&lock->sem_empty, shared, 0);
	if(ret)
		return -1;
	ret = sem_init(&lock->sem_full, shared, data->queue_cnt);
	if(ret)
		return -1;

	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_setrobust(&attr, 1);
	pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	pthread_mutex_init(&lock->mutex_lock, &attr);
	return 0;
}

static int create_and_init_queues(struct ipc_data *data)
{
	int ret;

	snprintf(data->metadata->meta_server_write.file_payload,
	         sizeof(data->metadata->meta_server_write.file_payload),
	         "%s_w_p", data->file_shm);
	snprintf(data->metadata->meta_server_write.file_locking,
	         sizeof(data->metadata->meta_server_write.file_locking),
	         "%s_w_l", data->file_shm);
	snprintf(data->metadata->meta_server_write.file_occupied,
	         sizeof(data->metadata->meta_server_write.file_occupied),
	         "%s_w_o", data->file_shm);

	snprintf(data->metadata->meta_server_read.file_payload,
	         sizeof(data->metadata->meta_server_read.file_payload),
	         "%s_r_p", data->file_shm);
	snprintf(data->metadata->meta_server_read.file_locking,
	         sizeof(data->metadata->meta_server_read.file_locking),
	         "%s_r_l", data->file_shm);
	snprintf(data->metadata->meta_server_read.file_occupied,
	         sizeof(data->metadata->meta_server_read.file_occupied),
	         "%s_r_o", data->file_shm);


	ret = create_shm(&data->fds.write.fd_payload,
	           data->metadata->meta_server_write.file_payload,
	           &data->write.shm_payload, data->payload_sz*data->queue_cnt);
	if(ret)
		return ret;

	ret = create_shm(&data->fds.write.fd_locking,
	           data->metadata->meta_server_write.file_locking,
	           (void**)&data->write.shm_locking, sizeof(struct ipc_queue_locking));
	if(ret)
		return ret;

	ret = create_shm(&data->fds.write.fd_occupied,
	           data->metadata->meta_server_write.file_occupied,
	           (void**)&data->write.shm_occupied,
	           sizeof(struct ipc_occupied)*data->queue_cnt);
	if(ret)
		return ret;

	ret = create_shm(&data->fds.read.fd_payload,
	           data->metadata->meta_server_read.file_payload,
	           &data->read.shm_payload, data->payload_sz*data->queue_cnt);
	if(ret)
		return ret;

	ret = create_shm(&data->fds.read.fd_locking,
	           data->metadata->meta_server_read.file_locking,
	           (void**)&data->read.shm_locking, sizeof(struct ipc_queue_locking));
	if(ret)
		return ret;

	ret = create_shm(&data->fds.read.fd_occupied,
	           data->metadata->meta_server_read.file_occupied,
	           (void**)&data->read.shm_occupied,
	           sizeof(struct ipc_occupied)*data->queue_cnt);
	if(ret)
		return ret;


	ret = init_locking(data, data->write.shm_locking);
	if(ret)
		return ret;

	ret = init_locking(data, data->read.shm_locking);
	return ret;
}

static int open_queues(struct ipc_data *data)
{
	/* Clients do the opposite than server */
	int ret;
	ret = open_shm(&data->fds.read.fd_payload,
	           data->metadata->meta_server_read.file_payload,
	           &data->write.shm_payload, data->payload_sz*data->queue_cnt);
	if(ret)
		return ret;

	ret = open_shm(&data->fds.read.fd_locking,
	           data->metadata->meta_server_read.file_locking,
	           (void**)&data->write.shm_locking, sizeof(struct ipc_queue_locking));
	if(ret)
		return ret;

	ret = open_shm(&data->fds.read.fd_occupied,
	           data->metadata->meta_server_read.file_occupied,
	           (void**)&data->write.shm_occupied,
	           sizeof(struct ipc_occupied)*data->queue_cnt);
	if(ret)
		return ret;

	ret = open_shm(&data->fds.write.fd_payload,
	           data->metadata->meta_server_write.file_payload,
	           &data->read.shm_payload, data->payload_sz*data->queue_cnt);
	if(ret)
		return ret;

	ret = open_shm(&data->fds.write.fd_locking,
	           data->metadata->meta_server_write.file_locking,
	           (void**)&data->read.shm_locking, sizeof(struct ipc_queue_locking));
	if(ret)
		return ret;

	ret = open_shm(&data->fds.write.fd_occupied,
	           data->metadata->meta_server_write.file_occupied,
	           (void**)&data->read.shm_occupied,
	           sizeof(struct ipc_occupied)*data->queue_cnt);

	return ret;
}

static int open_meta(struct ipc_data *data)
{
	int ret;
	int retries = 0;

	do {
		usleep(10000); /* Give some time of there is some concurrency */
		ret = open_shm(&data->fds.fd_queue_meta, data->file_queue_meta,
		               (void**)&data->metadata, sizeof(struct ipc_queue_meta));
		retries++;

	} while(-1 == ret && retries < OPEN_META_RETRIES);

	if(ret)
		return ret;

	while(!data->metadata->initialized)
		usleep(1000);

	return ret;
}

static int create_and_init_meta(struct ipc_data *data)
{
	int ret;
	ret = create_shm(&data->fds.fd_queue_meta, data->file_queue_meta,
	                 (void**)&data->metadata, sizeof(struct ipc_queue_meta));
	if(ret)
		return ret;

	data->metadata->queue_item_sz = data->payload_sz;
	data->metadata->queue_cnt = data->queue_cnt;
	data->metadata->queue_total_sz = data->payload_sz * data->queue_cnt;
	return ret;
}

static int init_meta(struct ipc_data *data)
{
	int ret;
	snprintf(data->file_queue_meta, sizeof(data->file_queue_meta),
	         "%s_meta", data->file_shm);

	switch(data->type) {
	case NODE_TYPE_CLIENT:
		ret = open_meta(data);
		if(
				data->payload_sz != data->metadata->queue_item_sz ||
				data->queue_cnt !=  data->metadata->queue_cnt

		)
			return -1;

		if(ret)
			return ret;
		ret = open_queues(data);
		if(ret)
			return ret;
		return 0;

	case NODE_TYPE_SERVER:
		ret = create_and_init_meta(data);
		if(ret)
			return ret;
		create_and_init_queues(data);
		if(ret)
			return ret;
		data->metadata->initialized = 1;
		return 0;
	default: return -1;
	}
}

int ipc_com_init(struct ipc_data **data, callback cb, char *shm_file,
                 enum NODE_TYPE type, int payload_sz, int queue_cnt)
{
	struct ipc_data *new_data;
	int ret;

	new_data = calloc(1, sizeof(*new_data));
	if(!data)
		return -ENOMEM;

	new_data->run = 1; /* can be started running */
	new_data->type = type;
	new_data->payload_sz = payload_sz;
	new_data->queue_cnt = queue_cnt;
	new_data->total_sz = payload_sz * queue_cnt;
	new_data->cb = cb;

	snprintf(new_data->file_shm, MAX_NAME_LEN, "/%s", shm_file);

	ret = init_meta(new_data);
	if(ret) {
		perror("ERROR HERE");
		return ret;
	}

	*data = new_data;
	return 0;

}

int ipc_com_destroy(struct ipc_data *data)
{
	if(data->type == NODE_TYPE_CLIENT) {
		free(data);
		return 0;
	}

	/* when server is going down, everything is freed */
	shm_unlink(data->metadata->meta_server_write.file_payload);
	close(data->fds.write.fd_payload);

	shm_unlink(data->metadata->meta_server_write.file_locking);
	close(data->fds.write.fd_locking);

	shm_unlink(data->metadata->meta_server_write.file_occupied);
	close(data->fds.write.fd_occupied);

	shm_unlink(data->metadata->meta_server_read.file_payload);
	close(data->fds.read.fd_payload);

	shm_unlink(data->metadata->meta_server_read.file_locking);
	close(data->fds.write.fd_locking);

	shm_unlink(data->metadata->meta_server_read.file_occupied);
	close(data->fds.write.fd_occupied);

	shm_unlink(data->metadata->file_queue_meta_write);
	close(data->fds.write.fd_queue_meta);
	shm_unlink(data->metadata->file_queue_meta_read);
	close(data->fds.read.fd_queue_meta);

	shm_unlink(data->file_queue_meta);
	close(data->fds.fd_queue_meta);

	free(data);
	return 0;
}

int ipc_com_start(struct ipc_data *data)
{
	int ret;
	ret = pthread_create(&data->run_thread, NULL, &thread_main, data);
	return ret;
}

int ipc_com_stop(struct ipc_data *data)
{
	int ret;
	data->run = 0;
	ret = pthread_join(data->run_thread, NULL);
	return ret;
}

int ipc_com_item_send(struct ipc_data *data, void *payload, int sz)
{
	int ret;
	struct ipc_occupied *occupied_ptr;
	ret = sem_wait(&data->write.shm_locking->sem_full);
	pthread_mutex_lock(&data->write.shm_locking->mutex_lock);

	if(sz > data->payload_sz)
		abort();

	occupied_ptr = data->write.shm_occupied;
	uint8_t *shm_payload = data->write.shm_payload;
	for(int i = 0; i < data->queue_cnt; ++i) {
		if(0 == occupied_ptr->allocated) {
			/* empty */
			occupied_ptr->allocated = 1;
			occupied_ptr->sz = sz;
			memcpy(shm_payload, payload, sz);
			break;
		}
		shm_payload += data->payload_sz;
	}
	pthread_mutex_unlock(&data->write.shm_locking->mutex_lock);
	ret = sem_post(&data->write.shm_locking->sem_empty);
	return ret;
}

// This is just for testing
/*
static void cb_method(void *payload, int sz)
{
	printf("CALLBACK FUNCTION\n");
}
int main(int argc, char * argv[])
{
	struct ipc_data *data;
	int ret;
	enum NODE_TYPE nt = NODE_TYPE_SERVER;
	if(argc == 2)
		nt = NODE_TYPE_CLIENT;

	ret = ipc_com_init(&data, &cb_method, "server_name", nt, 10, 2);
	if(ret) {
		printf("init failed...\n");
		return -1;
	}

	printf("OL\n");

	switch(nt){
	case NODE_TYPE_CLIENT: {
		uint8_t payload = 0xfe;
		int sz = sizeof(payload);
		for(int i = 0 ; i < 100 ; ++i) {
			printf("Sending %d\n", i);
			ipc_com_item_send(data, &payload, sz);
		}
	}
		break;
	case NODE_TYPE_SERVER: {
		ipc_com_start(data);
		for(int i = 0; i < 3; ++i){
			usleep(10000000);
		}
	}
		break;
	}
	ipc_com_stop(data);

	ipc_com_destroy(data);

//	int ret;
//	ret = init();
//	if(ret)
//		return ret;

}
*/
