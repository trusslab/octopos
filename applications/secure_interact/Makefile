umode:
	g++ -Wall -Werror -I ../../include/ secure_interact.c -o secure_interact.so -shared -fPIC -fvisibility=hidden
	mkdir -p ../bin
	cp secure_interact.so ../bin/

clean:
	rm secure_interact.so
