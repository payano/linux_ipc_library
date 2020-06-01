# linux_ipc_library
IPC library for linux

## How to try it out

```
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
}
```
