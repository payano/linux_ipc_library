#include "../ipc_com.h"
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

struct ipc_data *data;

void intHandler(int s) {
	printf("Caught signal %d\n",s);
	ipc_com_stop(data);
	ipc_com_destroy(data);
	exit(1);
}

static void cb_method(void *payload, int sz)
{
	uint8_t *value = payload;
	/* we know that this is a int... */
	printf("CALLBACK FUNCTION\n");
	printf("value: %d\n", *value);
}

#define PAYLOAD_SZ sizeof(uint8_t)

int main(int argc, char * argv[])
{
	signal (SIGINT, intHandler);

	int ret;
	enum NODE_TYPE nt = NODE_TYPE_SERVER;
	if(argc == 2)
		nt = NODE_TYPE_CLIENT;

	ret = ipc_com_init(&data, &cb_method, "data_test", nt, PAYLOAD_SZ*100, 10);
	if(ret) {
		printf("init failed...\n");
		return -1;
	}

	printf("STARTING...\n");

	switch(nt){
	case NODE_TYPE_CLIENT: {
		uint8_t payload = 0x0;
		int sz = sizeof(payload);
		for(int i = 0 ; i < 100 ; ++i) {
			printf("Sending %d, payload: %d\n", i, payload);
			ipc_com_item_send(data, &payload, PAYLOAD_SZ);
			payload++;
		}
	}
	break;
	case NODE_TYPE_SERVER: {
		ipc_com_start(data);
		while(1){
			usleep(10000000);
		}
	}
	break;
	}
	ipc_com_stop(data);

	ipc_com_destroy(data);
}
