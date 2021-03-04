UNTRUSTED_ROOT_FS_SRC_PATH=./arch/umode/untrusted_linux/CentOS6.x-AMD64-root_fs
UNTRUSTED_ROOT_FS_PARTITION_PATH=./storage/octopos_partition_1_data

./installer/installer
if [ ! -f $UNTRUSTED_ROOT_FS_PARTITION_PATH ]; then \
	cp $UNTRUSTED_ROOT_FS_SRC_PATH $UNTRUSTED_ROOT_FS_PARTITION_PATH; \
fi 
