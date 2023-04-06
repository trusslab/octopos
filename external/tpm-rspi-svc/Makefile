# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

APP = tpm-rspi-svc

# Add any other object files to this list below
APP_OBJS = tpm-rspi-svc.o tpm.o hash.o
LDFLAGS = -ldl -lpthread -lrt
LDLIBS = -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto -ljson-c

all: build

build: $(APP)

$(APP): $(APP_OBJS)
	$(CC) -o $@ $(APP_OBJS) $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(APP) *.o