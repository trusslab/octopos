all:
	g++ -Wall -Werror -I ../../include/ ipc_sender.c -o ipc_sender.so -shared -fPIC -fvisibility=hidden
	mkdir -p ../bin
	cp ipc_sender.so ../bin/
