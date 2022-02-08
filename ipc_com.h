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

#ifndef IPC_COM_H
#define IPC_COM_H

#ifdef __cplusplus
extern "C" {
#endif

struct ipc_data;
typedef void (*callback)(void *payload, int sz);

enum NODE_TYPE {
	NODE_TYPE_SERVER = 0x10,
	NODE_TYPE_CLIENT
};

/*
 * Create a new ipc_data and init it.
 */
/*
 * When leaving the callback method the payload is no longer available
 * The callback method needs to store it if they are interested in the data
 */
int ipc_com_init(struct ipc_data **data, callback cb, char *shm_file,
                 enum NODE_TYPE type, int payload_sz, int queue_cnt);
/*
 * Free up memory, ipc_data is no longer valid
 */
int ipc_com_destroy(struct ipc_data *data);
/*
 * Start the listening thread
 */
int ipc_com_start(struct ipc_data *data);
/*
 * Stop the listening thread
 */
int ipc_com_stop(struct ipc_data *data);

/*
 * Push the payload to the receiver
 */
int ipc_com_item_send(struct ipc_data *data, void *payload, int sz);

/*
 * Reserve one item, after the request is done, the queue will be locked until
 * ipc_com_item_release is called
 */
//int ipc_com_item_reserve(struct ipc_data *data, void *payload, int *msgSize);
//int ipc_com_item_release(struct ipc_data *data, int *writtenSz);

#ifdef __cplusplus
}
#endif

#endif /* STM32DRIVER_H_ */
