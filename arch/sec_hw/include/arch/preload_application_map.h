#ifndef SRC_OCTOPOS_ARCH_INCLUDE_ARCH_PRELOAD_APPLICATION_MAP_H_
#define SRC_OCTOPOS_ARCH_INCLUDE_ARCH_PRELOAD_APPLICATION_MAP_H_

#define NUM_APPLICATION 16

void* preloaded_apps[NUM_APPLICATION] = {0};
char* preloaded_app_names[NUM_APPLICATION] = {0};
u8 app_counter = 0;

void secure_interact(struct runtime_api *api);
void ipc_receiver(struct runtime_api *api);
void ipc_sender(struct runtime_api *api);
void secure_login(struct runtime_api *api);
void simple_loop(struct runtime_api *api);
void fs_test(struct runtime_api *api);
void socket_client(struct runtime_api *api);
void storage_benchmark(struct runtime_api *api);
void serial_benchmark(struct runtime_api *api);

void set_app(char* app_name, void* app_addr)
{
	preloaded_apps[app_counter] = app_addr;
	char* app_name_copy = malloc(strlen(app_name)+1);
	if(!app_name_copy)
		return;
	strcpy(app_name_copy, app_name);
	preloaded_app_names[app_counter] = app_name_copy;
	++app_counter;
}

void* get_app(char* app_name)
{
	for(int i = 0; i < app_counter; ++i) {
		if(!strcmp(preloaded_app_names[i], app_name))
			return preloaded_apps[i];
	}
	return NULL;
}

void preloaded_app_init()
{
	/* only enable needed applications to save heap space */
//	set_app("secure_login", (void*) secure_login);
//	set_app("secure_interact", (void*) secure_interact);
//	set_app("ipc_receiver", (void*) ipc_receiver);
//	set_app("ipc_sender", (void*) ipc_sender);
//	set_app("simple_loop", (void*) simple_loop);
	set_app("fs_test", (void*) fs_test);
	set_app("socket_client", (void*) socket_client);
//	set_app("storage_benchmark",(void*) storage_benchmark);
	set_app("serial_benchmark",(void*) serial_benchmark);
}

void* preloaded_app(char* app_name)
{
	return get_app(app_name);
}

void preloaded_app_destroy()
{
	for(int i = 0; i < app_counter; ++i) {
		free(preloaded_app_names[i]);
	}
}
#endif /* SRC_OCTOPOS_ARCH_INCLUDE_ARCH_PRELOAD_APPLICATION_MAP_H_ */
