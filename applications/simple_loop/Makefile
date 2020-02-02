umode:
	g++ -Wall -Werror -I ../../include/ simple_loop.c -o simple_loop.so -shared -fPIC -fvisibility=hidden
	mkdir -p ../bin
	cp simple_loop.so ../bin/

clean:
	rm simple_loop.so
