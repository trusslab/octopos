umode:
	g++ -Wall -Werror -I ../../../include/ -I ../include/ ../../../util/tpm/hash.c ../../../util/tpm/tpm.c pmu.c -o pmu -lpthread -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto

clean:
	rm pmu
