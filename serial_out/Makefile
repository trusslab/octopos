umode:
	g++ -Wall -Werror -I ../include/ -I ../arch/umode/include/ -I ../arch/umode/include/ serial_out.c -o serial_out.so ../arch/umode/mailbox_interface/mailbox_serial_out.c -shared -fPIC -lpthread -lrt

clean:
	rm serial_out
