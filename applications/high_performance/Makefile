umode:
	g++ -Wall -I ../../include/ matrix_left.c emu_sys.c -o matrix_left.so -shared -fPIC -fvisibility=hidden
	g++ -Wall -I ../../include/ matrix_right.c emu_sys.c -o matrix_right.so -shared -fPIC -fvisibility=hidden
	mkdir -p ../bin
	cp matrix_left.so ../bin/
	cp matrix_right.so ../bin/

clean:
	rm matrix_left.so
	rm matrix_right.so
