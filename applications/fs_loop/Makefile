all:
	g++ -Wall -Werror -I ../../include/ fs_loop.c -o fs_loop.so -shared -fPIC -fvisibility=hidden
	mkdir -p ../bin
	cp fs_loop.so ../bin/
