#ifndef SRC_OCTOPOS_ARCH_INCLUDE_ARCH_PRELOAD_APPLICATION_MAP_H_
#define SRC_OCTOPOS_ARCH_INCLUDE_ARCH_PRELOAD_APPLICATION_MAP_H_

#define NUM_APPLICATION 16

void* preloaded_apps[NUM_APPLICATION] = {0};
char* preloaded_app_names[NUM_APPLICATION] = {0};
u8 app_counter = 0;

void secure_interact(struct runtime_api *api);
void ipc_receiver(struct runtime_api *api);
void ipc_sender(struct runtime_api *api);
void secure_interact(struct runtime_api *api);

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
	set_app("secure_login", (void*) secure_login);
	set_app("secure_interact", (void*) secure_interact);
	set_app("ipc_receiver", (void*) ipc_receiver);
	set_app("ipc_sender", (void*) ipc_sender);
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
