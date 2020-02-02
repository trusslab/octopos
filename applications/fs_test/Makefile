umode:
	g++ -Wall -Werror -I ../../include/ fs_test.c -o fs_test.so -shared -fPIC -fvisibility=hidden
	mkdir -p ../bin
	cp fs_test.so ../bin/

clean:
	rm fs_test.so
