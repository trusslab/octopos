umode:
	g++ -Wall -I ../../include/ high_performance.c -o high_performance.so -shared -fPIC -lrt -lpthread -fvisibility=hidden
	mkdir -p ../bin
	cp high_performance.so ../bin/

clean:
	rm high_performance.so
