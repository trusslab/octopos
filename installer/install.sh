# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

UNTRUSTED_ROOT_FS_SRC_PATH=./arch/umode/untrusted_linux/CentOS6.x-AMD64-root_fs
UNTRUSTED_ROOT_FS_PARTITION_PATH=./storage/octopos_partition_1_data

./installer/installer
if [ ! -f $UNTRUSTED_ROOT_FS_PARTITION_PATH ]; then \
	cp $UNTRUSTED_ROOT_FS_SRC_PATH $UNTRUSTED_ROOT_FS_PARTITION_PATH; \
fi 
