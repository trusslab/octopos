umode:
	g++ -Wall -Werror -I ../../include/ high_performance.c -o high_performance.so -shared -fPIC -lpthread -fvisibility=hidden
	mkdir -p ../bin
	cp high_performance.so ../bin/

clean:
	rm high_performance.so
