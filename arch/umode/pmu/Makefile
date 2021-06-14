umode:
	g++ -Wall -Werror -I ../../../include/ -I ../include/ pmu.c ../../../util/tpm/hash.c ../../../util/tpm/tpm.c ../../../util/tpm/queue.c -o pmu -lpthread -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto -lrt

clean:
	rm pmu
