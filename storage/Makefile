umode:
	g++ -Wall -Werror -I ../include/ -I ../arch/umode/include/ storage.c ../arch/umode/mailbox_interface/mailbox_storage.c -o storage.so -shared -fPIC -lpthread -lrt

clean:
	rm storage.so
