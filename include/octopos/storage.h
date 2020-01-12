#define STORAGE_KEY_SIZE	32  /* bytes */

#define STORAGE_OP_WRITE	0
#define STORAGE_OP_READ		1
#define STORAGE_OP_SET_KEY	2
#define STORAGE_OP_REMOVE_KEY	3
#define STORAGE_OP_UNLOCK	4
#define STORAGE_OP_WIPE		5

#define STORAGE_BLOCK_SIZE	32  /* bytes */
#define STORAGE_MAIN_PARTITION_SIZE	1000  /* num blocks */
