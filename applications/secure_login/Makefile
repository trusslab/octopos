all:
	g++ secure_login.c -o secure_login.so -shared -fPIC -fvisibility=hidden
	mkdir -p ../bin
	cp secure_login.so ../bin/
