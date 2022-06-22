APP = tpm-client

# Add any other object files to this list below
APP_OBJS = tpm-client.o tpm.o hash.o

all: build

build: $(APP)

$(APP): $(APP_OBJS)
	$(CC) -o $@ $(APP_OBJS) $(LDFLAGS) $(LDLIBS) -ldl -lpthread -lrt -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto -ljson-c
clean:
	rm -f $(APP) *.o


