#ifdef ARCH_SEC_HW_STORAGE
#include <stdio.h>
#include <stdlib.h>
#include "xil_printf.h"
#include "sleep.h"
#include "xstatus.h"
#include "xmbox.h"
#include "xintc.h"

#include "ff.h"

#include "arch/sec_hw.h"
#include "arch/semaphore.h"
#include "arch/ring_buffer.h"

#include "octopos/mailbox.h"
#include "octopos/storage.h"
#include "octopos/error.h"

XIntc			intc;

XMbox			Mbox_storage_in_2,
				Mbox_storage_out_2,
				Mbox_storage_cmd_in,
				Mbox_storage_cmd_out,
				Mbox_storage_data_in,
				Mbox_storage_data_out;

sem_t			interrupts[NUM_QUEUES + 1];

XMbox*			Mbox_regs[NUM_QUEUES + 1];
UINTPTR			Mbox_ctrl_regs[NUM_QUEUES + 1];

static FATFS	fatfs;

bool is_queue_set_bound = false;
int bound_partition = -1;

/* https://stackoverflow.com/questions/7775027/how-to-create-file-of-x-size */
static void initialize_storage_space(void)
{
	TCHAR *Path = "0:/";
	BYTE work[FF_MAX_SS];
	FRESULT result;
	FIL filep, filep2;
	UINT NumBytesRead = 0;

	result = f_mount(&fatfs, Path, 0);
	if (result != FR_OK) {
		SEC_HW_DEBUG_HANG();
		return;
	}

	result = f_mkfs(Path, FM_FAT, 0, work, sizeof work);
	if (result != FR_OK) {
		SEC_HW_DEBUG_HANG();
		return;
	}

	for (int i = 0; i < (NUM_SEC_PARTITIONS + 1); i++) {
		struct partition *partition;
		int suffix = 0;
		if (i == 0) {
			partition = &main_partition;
			partition->size = STORAGE_MAIN_PARTITION_SIZE;
			suffix = 1;
		} else {
			partition = &sec_partitions[i - 1];
			partition->size = STORAGE_SECURE_PARTITION_SIZE;
			suffix = i + 1;
		}

		memset(partition->data_name, 0x0, 256);
		sprintf(partition->data_name, "octopos_partition_%d_data", suffix);

		memset(partition->create_name, 0x0, 256);
		sprintf(partition->create_name, "octopos_partition_%d_create", suffix);

		memset(partition->lock_name, 0x0, 256);
		sprintf(partition->lock_name, "octopos_partition_%d_lock", suffix);

		result = f_open(&filep, partition->data_name, FA_READ);
		if (result) {
			/* create empty file */
			f_open(&filep2, partition->data_name, FA_CREATE_ALWAYS | FA_WRITE);
			f_close(&filep2);
		}

		/* Is partition created? */
		result = f_open(&filep, partition->create_name, FA_READ);
		if (result) {
			/* create empty file */
			f_open(&filep2, partition->create_name, FA_CREATE_ALWAYS | FA_WRITE);
			f_close(&filep2);
			/* Also wipe lock info (which should not have any valid key anyway. */
			f_open(&filep2, partition->lock_name, FA_CREATE_ALWAYS | FA_WRITE);
			f_close(&filep2);
			partition->is_locked = false;
			continue;
		}

		f_lseek(&filep, 0);
		uint32_t tag = 0;

		f_read(&filep, &tag, 4, &NumBytesRead);
		f_close(&filep);
		if (NumBytesRead == 4 && tag == 1) {
			partition->is_created = true;
		} else {
			/* create empty file */
			f_open(&filep2, partition->create_name, FA_CREATE_ALWAYS | FA_WRITE);
			f_close(&filep2);
			/* Also wipe any key info. This should not normally happen. */
			f_open(&filep2, partition->lock_name, FA_CREATE_ALWAYS | FA_WRITE);
			f_close(&filep2);
			partition->is_locked = false;
			continue;
		}

		/* lock partitions that have an active key */
		result = f_open(&filep, partition->lock_name, FA_READ);
		if (result) {
			/* create empty file */
			f_open(&filep2, partition->lock_name, FA_CREATE_ALWAYS | FA_WRITE);
			f_close(&filep2);
			partition->is_locked = false;
			continue;
		}

		uint8_t key[STORAGE_KEY_SIZE];
		f_lseek(&filep, 0);
		f_read(&filep, key, STORAGE_KEY_SIZE, &NumBytesRead);
		f_close(&filep);
		if (NumBytesRead == STORAGE_KEY_SIZE) {
			partition->is_locked = true;
		} else {
			/* wipe lock file */
			f_open(&filep2, partition->lock_name, FA_CREATE_ALWAYS | FA_WRITE);
			f_close(&filep2);
			partition->is_locked = false;
		}
	}
}


static int set_secure_partition_key(uint8_t *data, int partition_id)
{
	FRESULT result;
	FIL filep;
	UINT NumBytesWritten = 0;

	result = f_open(&filep, sec_partitions[partition_id].lock_name, FA_READ | FA_WRITE);
	if (result) {
		_SEC_HW_ERROR("%s: Error: couldn't open %s\n", __func__, sec_partitions[partition_id].lock_name);
		return ERR_FAULT;
	}

	f_lseek(&filep, 0);
	f_write(&filep, (const void*)data, STORAGE_KEY_SIZE, &NumBytesWritten);

	if (NumBytesWritten < STORAGE_KEY_SIZE) {
		/* make sure to delete what was written */
		f_open(&filep, sec_partitions[partition_id].lock_name, FA_CREATE_ALWAYS | FA_WRITE);
		f_close(&filep);
		return ERR_FAULT;
	}

	return 0;
}

static int remove_partition_key(int partition_id)
{
	FIL filep;
	FRESULT result;

	result = f_open(&filep, sec_partitions[partition_id].lock_name, FA_CREATE_ALWAYS | FA_WRITE);

	if (result) {
		_SEC_HW_ERROR("%s: Error: couldn't open %s\n", __func__, sec_partitions[partition_id].lock_name);
		return ERR_FAULT;
	}
	f_close(&filep);
	return 0;
}

static int unlock_partition(uint8_t *data, int partition_id)
{
	FIL filep;
	FRESULT result;
	UINT NumBytesRead = 0;
	uint8_t key[STORAGE_KEY_SIZE];

	result = f_open(&filep, sec_partitions[partition_id].lock_name, FA_READ);

	if (result) {
		_SEC_HW_ERROR("%s: Error: couldn't open %s\n", __func__, sec_partitions[partition_id].lock_name);
		return ERR_FAULT;
	}

	f_lseek(&filep, 0);
	f_read(&filep, (void*)key, STORAGE_KEY_SIZE, &NumBytesRead);
	f_close(&filep);
	if (NumBytesRead != STORAGE_KEY_SIZE) {
		/* TODO: if the key file is corrupted, then we might need to unlock, otherwise, we'll lose the partition. */
		return ERR_FAULT;
	}

	for (int i = 0; i < STORAGE_KEY_SIZE; i++) {
		if (key[i] != data[i])
			return ERR_INVALID;
	}

	sec_partitions[partition_id].is_locked = false;
	return 0;
}

static int wipe_partition(int partition_id)
{
	FIL filep;
	FRESULT result;

	result = f_open(&filep, sec_partitions[partition_id].data_name, FA_CREATE_ALWAYS | FA_WRITE);

	if (result) {
		_SEC_HW_ERROR("%s: Error: couldn't open %s\n", __func__, sec_partitions[partition_id].data_name);
		return ERR_FAULT;
	}
	f_close(&filep);
	return 0;
}


static void process_request(uint8_t *buf)
{
	FIL filep, filep2;
	FRESULT result;
	UINT NumBytesRead = 0, NumBytesWritten = 0;

	/* write */
	if (buf[0] == STORAGE_OP_WRITE) {
		if (main_partition.is_locked) {
			_SEC_HW_ERROR("%s: Error: partition is locked\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}
		result = f_open(&filep, main_partition.data_name, FA_READ | FA_WRITE);
		if (result) {
			_SEC_HW_ERROR("%s: Error: couldn't open %s for write\n", __func__, main_partition.data_name);
			STORAGE_SET_ONE_RET(0)
			return;
		}
		STORAGE_GET_TWO_ARGS
		int start_block = (int) arg0;
		int num_blocks = (int) arg1;
		if (start_block + num_blocks >= main_partition.size) {
			_SEC_HW_ERROR("%s: Error: invalid args\n", __func__);
			STORAGE_SET_ONE_RET(0)
			f_close(&filep);
			return;
		}
		int seek_off = start_block * STORAGE_BLOCK_SIZE;
		f_lseek(&filep, seek_off);
		uint8_t data_buf[STORAGE_BLOCK_SIZE];
		uint32_t size = 0;
		for (int i = 0; i < num_blocks; i++) {
			read_data_from_queue(data_buf, Q_STORAGE_DATA_IN);
			f_write(&filep, (const void*)data_buf, STORAGE_BLOCK_SIZE, &NumBytesWritten);
			size += (uint32_t) NumBytesWritten;
		}
		STORAGE_SET_ONE_RET(size);
		f_close(&filep);
	} else if (buf[0] == STORAGE_OP_READ) { /* read */
		if (main_partition.is_locked) {
			_SEC_HW_ERROR("%s: Error: partition is locked\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}
		result = f_open(&filep, main_partition.data_name, FA_READ);
		if (result) {
			_SEC_HW_ERROR("%s: Error: couldn't open %s for read\n", __func__, main_partition.data_name);
			STORAGE_SET_ONE_RET(0)
			return;
		}
		STORAGE_GET_TWO_ARGS
		int start_block = (int) arg0;
		int num_blocks = (int) arg1;
		if (start_block + num_blocks >= main_partition.size) {
			_SEC_HW_ERROR("%s: Error: invalid args\n", __func__);
			STORAGE_SET_ONE_RET(0)
			f_close(&filep);
			return;
		}
		int seek_off = start_block * STORAGE_BLOCK_SIZE;
		f_lseek(&filep, seek_off);
		uint8_t data_buf[STORAGE_BLOCK_SIZE];
		uint32_t size = 0;
		for (int i = 0; i < num_blocks; i++) {
			f_read(&filep, (void*)data_buf, STORAGE_BLOCK_SIZE, &NumBytesRead);
			size += (uint32_t) NumBytesRead;
			write_data_to_queue(data_buf, Q_STORAGE_DATA_OUT);
		}
		STORAGE_SET_ONE_RET(size);
		f_close(&filep);
	/* creates a new secure partition */
	/* FIXME: temp implementation */
	} else if (buf[0] == STORAGE_OP_CREATE_SECURE_PARTITION) {
		STORAGE_GET_ZERO_ARGS_DATA
		if (data_size != STORAGE_KEY_SIZE) {
			_SEC_HW_ERROR("%s: Error: incorrect key size\n", __func__);
			STORAGE_SET_TWO_RETS(ERR_INVALID, 0)
			return;
		}

		int partition_id = -1;

		for (int i = 0; i < NUM_SEC_PARTITIONS; i++) {
			if (!sec_partitions[i].is_created) {
				partition_id = i;
				break;
			}
		}

		if (partition_id < 0 || partition_id >= NUM_SEC_PARTITIONS) {
			_SEC_HW_ERROR("%s: Error: no secure partitions available\n", __func__);
			STORAGE_SET_TWO_RETS(ERR_AVAILABLE, 0)
			return;
		}

		int ret = set_secure_partition_key(data, partition_id);
		if (ret) {
			STORAGE_SET_TWO_RETS(ERR_FAULT, 0)
			return;
		}

		result = f_open(&filep, sec_partitions[partition_id].create_name, FA_READ | FA_WRITE);
		if (result) {
			STORAGE_SET_TWO_RETS(ERR_FAULT, 0)
			return;
		}

		f_lseek(&filep, 0);
		uint32_t tag = 1;
		f_write(&filep, (const void*)&tag, 4, &NumBytesWritten);
		uint32_t size = NumBytesWritten;
		f_close(&filep);
		if (size != 4) {
			STORAGE_SET_TWO_RETS(ERR_FAULT, 0)
			if (size > 0) { /* partial write */
				/* wipe the file */
				f_open(&filep2, sec_partitions[partition_id].create_name, FA_CREATE_ALWAYS | FA_WRITE);
				f_close(&filep2);
			}
			return;
		}

		sec_partitions[partition_id].is_created = true;

		STORAGE_SET_TWO_RETS(0, partition_id)
	} else if (buf[0] == STORAGE_OP_DELETE_SECURE_PARTITION) {
		STORAGE_GET_ONE_ARG
		uint32_t sec_partition_id = arg0;

		if (sec_partition_id >= NUM_SEC_PARTITIONS) {
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		if (!sec_partitions[sec_partition_id].is_created) {
			_SEC_HW_ERROR("%s: Error: secure partition does not exist\n", __func__);
			STORAGE_SET_ONE_RET(ERR_EXIST)
			return;
		}

		if (is_queue_set_bound && (bound_partition == (int) sec_partition_id)) {
			_SEC_HW_ERROR("%s: Error: secure partition currently bound to a queue set\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}
		if (sec_partitions[sec_partition_id].is_locked) {
			_SEC_HW_ERROR("%s: Error: can't delete a locked partition\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		sec_partitions[sec_partition_id].is_created = false;
		/* wipe the create and lock files of the partition */
		f_open(&filep2, sec_partitions[sec_partition_id].create_name, FA_CREATE_ALWAYS | FA_WRITE);
		f_close(&filep2);
		f_open(&filep2, sec_partitions[sec_partition_id].lock_name, FA_CREATE_ALWAYS | FA_WRITE);
		f_close(&filep2);

		STORAGE_SET_ONE_RET(0)
	} else {
		STORAGE_SET_ONE_RET(ERR_INVALID)
		return;
	}
}

/* FIXME: there's duplicate code between process_request and this function */
static void process_secure_request(uint8_t *buf)
{
	FIL filep, filep2;
	FRESULT result;
	UINT NumBytesRead = 0, NumBytesWritten = 0;

	/* write */
	if (buf[0] == STORAGE_OP_WRITE) {
		if (!is_queue_set_bound) {
			_SEC_HW_ERROR("%s: Error: no partition is bound to queue set\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}

		int partition_id = bound_partition;

		if (partition_id < 0 || partition_id >= NUM_SEC_PARTITIONS) {
			_SEC_HW_ERROR("%s: Error: invalid partition ID\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}

		if (sec_partitions[partition_id].is_locked) {
			_SEC_HW_ERROR("%s: Error: partition is locked\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}

		result = f_open(&filep, sec_partitions[partition_id].data_name, FA_READ | FA_WRITE);
		if (result) {
			_SEC_HW_ERROR("%s: Error: couldn't open %s for write\n", __func__, sec_partitions[partition_id].data_name);
			STORAGE_SET_ONE_RET(0)
			return;
		}

		STORAGE_GET_TWO_ARGS_DATA
		if (((int) arg0) > sec_partitions[partition_id].size) {
			_SEC_HW_ERROR("%s: Error: invalid block size\n", __func__);
			STORAGE_SET_ONE_RET(0)
			f_close(&filep);
			return;
		}

		int seek_off = (arg0 * STORAGE_BLOCK_SIZE) + arg1;
		f_lseek(&filep, seek_off);
		f_write(&filep, (const void*)data, data_size, &NumBytesWritten);
		uint32_t size = NumBytesWritten;

		STORAGE_SET_ONE_RET(size);
		f_close(&filep);
	} else if (buf[0] == STORAGE_OP_READ) { /* read */
		if (!is_queue_set_bound) {
			_SEC_HW_ERROR("%s: Error: no partition is bound to queue set\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}

		int partition_id = bound_partition;

		if (partition_id < 0 || partition_id >= NUM_SEC_PARTITIONS) {
			_SEC_HW_ERROR("%s: Error: invalid partition ID\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}

		if (sec_partitions[partition_id].is_locked) {
			_SEC_HW_ERROR("%s: Error: partition is locked\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}

		result = f_open(&filep, sec_partitions[partition_id].data_name, FA_READ);
		if (result) {
			_SEC_HW_ERROR("%s: Error: couldn't open %s for read\n", __func__, sec_partitions[partition_id].data_name);
			STORAGE_SET_ONE_RET(0)
			return;
		}

		STORAGE_GET_THREE_ARGS
		if (((int) arg0) > sec_partitions[partition_id].size) {
			_SEC_HW_ERROR("%s: Error: invalid block size\n", __func__);
			STORAGE_SET_ONE_RET(0)
			f_close(&filep);
			return;
		}

		uint8_t ret_buf[MAILBOX_QUEUE_MSG_SIZE];
		int seek_off = (arg0 * STORAGE_BLOCK_SIZE) + arg1;
		f_lseek(&filep, seek_off);
		f_read(&filep, ret_buf, arg2, &NumBytesRead);
		uint32_t size = (uint32_t) NumBytesRead;

		STORAGE_SET_ONE_RET_DATA(size, ret_buf, size);
		f_close(&filep);
	} else if (buf[0] == STORAGE_OP_SET_KEY) {
		if (!is_queue_set_bound) {
			_SEC_HW_ERROR("%s: Error: no partition is bound to queue set\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		int partition_id = bound_partition;

		if (partition_id < 0 || partition_id >= NUM_SEC_PARTITIONS) {
			_SEC_HW_ERROR("%s: Error: invalid partition ID\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		if (sec_partitions[partition_id].is_locked) {
			_SEC_HW_ERROR("%s: Error: can't set the key for a locked partition\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		STORAGE_GET_ZERO_ARGS_DATA
		if (data_size != STORAGE_KEY_SIZE) {
			_SEC_HW_ERROR("%s: Error: incorrect key size\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		uint32_t ret = (uint32_t) set_secure_partition_key(data, partition_id);
		STORAGE_SET_ONE_RET(ret)
	} else if (buf[0] == STORAGE_OP_UNLOCK) {
		STORAGE_GET_ZERO_ARGS_DATA
		if (data_size != STORAGE_KEY_SIZE) {
			_SEC_HW_ERROR("%s: Error: incorrect key size (sent for unlocking)\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		int partition_id = -1;

		for (int i = 0; i < NUM_SEC_PARTITIONS; i++) {
			int ret = unlock_partition(data, i);
			if (!ret) {
				partition_id = i;
				break;
			}
		}

		if (partition_id < 0 || partition_id >= NUM_SEC_PARTITIONS) {
			STORAGE_SET_ONE_RET(ERR_EXIST)
			return;
		}

		if (sec_partitions[partition_id].is_locked) {
			STORAGE_SET_ONE_RET(ERR_FAULT)
			return;
		}

		bound_partition = partition_id;
		is_queue_set_bound = true;

		STORAGE_SET_ONE_RET(0)
	} else if (buf[0] == STORAGE_OP_LOCK) {
		if (!is_queue_set_bound) {
			_SEC_HW_ERROR("%s: Error: no partition is bound to queue set\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		int partition_id = bound_partition;

		if (partition_id < 0 || partition_id >= NUM_SEC_PARTITIONS) {
			_SEC_HW_ERROR("%s: Error: invalid partition ID\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		sec_partitions[partition_id].is_locked = true;
		bound_partition = -1;
		is_queue_set_bound = false;

		STORAGE_SET_ONE_RET(0)
	} else if (buf[0] == STORAGE_OP_WIPE) {
		if (!is_queue_set_bound) {
			_SEC_HW_ERROR("%s: Error: no partition is bound to queue set\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		int partition_id = bound_partition;

		if (partition_id < 0 || partition_id >= NUM_SEC_PARTITIONS) {
			_SEC_HW_ERROR("%s: Error: invalid partition ID\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}
		if (sec_partitions[partition_id].is_locked) {
			_SEC_HW_ERROR("%s: Error: partition is locked\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}
		int ret = wipe_partition(partition_id);
		if (ret) {
			_SEC_HW_ERROR("%s: Error: couldn't wipe the partition\n", __func__);
			STORAGE_SET_ONE_RET(ERR_FAULT)
			return;
		}

		ret = remove_partition_key(partition_id);
		if (ret) {
			_SEC_HW_ERROR("%s: Error: couldn't remove partition key\n", __func__);
			STORAGE_SET_ONE_RET(ERR_FAULT)
			return;
		}

		bound_partition = -1;
		is_queue_set_bound = false;

		STORAGE_SET_ONE_RET(0)
	} else {
		STORAGE_SET_ONE_RET(ERR_INVALID)
		return;
	}
}

static void handle_mailbox_interrupts(void* callback_ref)
{
	u32         mask;
	XMbox       *mbox_inst = (XMbox *)callback_ref;

	_SEC_HW_DEBUG("Mailbox ref: %p", callback_ref);
	mask = XMbox_GetInterruptStatus(mbox_inst);

	if (mask & XMB_IX_STA) {
		_SEC_HW_DEBUG("interrupt type: XMB_IX_STA");
		if (callback_ref == &Mbox_storage_cmd_out) {
			sem_post(&interrupts[Q_STORAGE_CMD_OUT]);
		} else if (callback_ref == &Mbox_storage_data_out) {
			sem_post(&interrupts[Q_STORAGE_DATA_OUT]);
		} else if (callback_ref == &Mbox_storage_out_2) {
			sem_post(&interrupts[Q_STORAGE_OUT_2]);
		}
	} else if (mask & XMB_IX_RTA) {
		_SEC_HW_DEBUG("interrupt type: XMB_IX_RTA");
		if (callback_ref == &Mbox_storage_cmd_in) {
			sem_post(&interrupts[Q_STORAGE_CMD_IN]);
		} else if (callback_ref == &Mbox_storage_data_in) {
			sem_post(&interrupts[Q_STORAGE_DATA_IN]);
		} else if (callback_ref == &Mbox_storage_in_2) {
			sem_post(&interrupts[Q_STORAGE_IN_2]);
			sem_post(&interrupts[Q_STORAGE_CMD_IN]);
		}
	} else if (mask & XMB_IX_ERR) {
		_SEC_HW_ERROR("interrupt type: XMB_IX_ERR, from %p", callback_ref);
	} else {
		_SEC_HW_ERROR("interrupt type unknown, mask %d, from %p", mask, callback_ref);
	}

	XMbox_ClearInterrupt(mbox_inst, mask);

	_SEC_HW_DEBUG("interrupt cleared");
}

/* duplicate as in mailbox_os.c */
_Bool handle_partial_message(uint8_t *message_buffer, uint8_t *queue_id, u32 bytes_read) 
{
	/* Same handling logic as in semaphore.c
	 * If the message is incomplete due to sync issues, try to collect
	 * the rest of the message in the next read.
	 */
	_SEC_HW_DEBUG1("queue %d read only %d bytes, should be %d bytes",
		*queue_id, bytes_read, MAILBOX_QUEUE_MSG_SIZE);
	if (!sketch_buffer[*queue_id]) {
		_SEC_HW_DEBUG1("new sktech_buffer", *queue_id);
		sketch_buffer_offset[*queue_id] = bytes_read;
		sketch_buffer[*queue_id] = (uint8_t*) calloc(MAILBOX_QUEUE_MSG_SIZE, sizeof(uint8_t));
		memcpy(sketch_buffer[*queue_id], message_buffer, bytes_read);
		*queue_id = 0;
		return FALSE;
	} else {
		/* There is already a incomplete message on the sketch_buffer */
		if (bytes_read + sketch_buffer_offset[*queue_id] > MAILBOX_QUEUE_MSG_SIZE) {
			_SEC_HW_ERROR("mailbox corrupted: buffer overflow");
			_SEC_HW_ASSERT_NON_VOID(FALSE)
		}

		memcpy(sketch_buffer[*queue_id] + sketch_buffer_offset[*queue_id],
				message_buffer, bytes_read);
		if (bytes_read + sketch_buffer_offset[*queue_id] == MAILBOX_QUEUE_MSG_SIZE) {
			/* This read completes the message */
			_SEC_HW_DEBUG1("complete sketch_buffer");
			memcpy(message_buffer, sketch_buffer[*queue_id], MAILBOX_QUEUE_MSG_SIZE);
			free(sketch_buffer[*queue_id]);
			sketch_buffer[*queue_id] = NULL;
			return TRUE;
		} else {
			/* The message is still incomplete after this read */
			_SEC_HW_DEBUG1("partially full sketch_buffer");
			*queue_id = 0;
			return FALSE;
		}

	}
}

void storage_event_loop(void)
{
	u32 bytes_read;
	uint8_t queue_id = 0;
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	int is_secure_queue = 0;
	
	while(1) {
		memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
		sem_wait(&interrupts[Q_STORAGE_CMD_IN]);
		sem_getvalue(&interrupts[Q_STORAGE_IN_2], &is_secure_queue);
		if (!is_secure_queue) {
#ifdef HW_MAILBOX_BLOCKING
			XMbox_ReadBlocking(&Mbox_storage_cmd_in, (u32*) buf, MAILBOX_QUEUE_MSG_SIZE);
#else
			queue_id = Q_STORAGE_CMD_IN;
			XMbox_Read(&Mbox_storage_cmd_in,
				(u32*) buf,
				MAILBOX_QUEUE_MSG_SIZE,
				&bytes_read);
			if (bytes_read != MAILBOX_QUEUE_MSG_SIZE &&
				!handle_partial_message(buf, &queue_id, bytes_read))
#endif
			process_request(buf);
			XMbox_WriteBlocking(&Mbox_storage_cmd_out, buf, MAILBOX_QUEUE_MSG_SIZE)
		} else {
			sem_wait(&interrupts[Q_STORAGE_IN_2]);
#ifdef HW_MAILBOX_BLOCKING
			XMbox_ReadBlocking(&Mbox_storage_in_2, (u32*) buf, MAILBOX_QUEUE_MSG_SIZE);
#else
			queue_id = Q_STORAGE_IN_2;
			XMbox_Read(&Mbox_storage_in_2,
				(u32*) buf,
				MAILBOX_QUEUE_MSG_SIZE,
				&bytes_read);
			if (bytes_read != MAILBOX_QUEUE_MSG_SIZE &&
				!handle_partial_message(buf, &queue_id, bytes_read))
#endif
			process_secure_request(buf);
			XMbox_WriteBlocking(&Mbox_storage_out_2, buf, MAILBOX_QUEUE_MSG_SIZE)
		}
	}
}

int init_storage(void)
{
	int				Status;
	XMbox_Config	*Config_cmd_out, 
					*Config_cmd_in, 
					*Config_Data_out, 
					*Config_Data_in, 
					*Config_storage_in_2, 
					*Config_storage_out_2;

	/* Initialize XMbox */
	Config_cmd_in = XMbox_LookupConfig(XPAR_Q_STORAGE_CMD_IN_IF_1_DEVICE_ID);
	Status = XMbox_CfgInitialize(&Mbox_storage_cmd_in, Config_cmd_in, Config_cmd_in->BaseAddress);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XMbox_CfgInitialize %d failed", XPAR_Q_STORAGE_CMD_IN_IF_1_DEVICE_ID);
		return XST_FAILURE;
	}

	Config_cmd_out = XMbox_LookupConfig(XPAR_Q_STORAGE_CMD_OUT_IF_1_DEVICE_ID);
	Status = XMbox_CfgInitialize(&Mbox_storage_cmd_out, Config_cmd_out, Config_cmd_out->BaseAddress);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XMbox_CfgInitialize %d failed", XPAR_Q_STORAGE_CMD_OUT_IF_1_DEVICE_ID);
		return XST_FAILURE;
	}

	Config_Data_in = XMbox_LookupConfig(XPAR_MAILBOX_1_IF_0_DEVICE_ID);
	Status = XMbox_CfgInitialize(&Mbox_storage_data_in, Config_Data_in, Config_Data_in->BaseAddress);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XMbox_CfgInitialize %d failed", XPAR_MAILBOX_1_IF_0_DEVICE_ID);
		return XST_FAILURE;
	}

	Config_Data_out = XMbox_LookupConfig(XPAR_MAILBOX_2_IF_0_DEVICE_ID);
	Status = XMbox_CfgInitialize(&Mbox_storage_data_out, Config_Data_out, Config_Data_out->BaseAddress);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XMbox_CfgInitialize %d failed", XPAR_MAILBOX_2_IF_0_DEVICE_ID);
		return XST_FAILURE;
	}

	Config_storage_in_2 = XMbox_LookupConfig(XPAR_MAILBOX_3_IF_0_DEVICE_ID);
	Status = XMbox_CfgInitialize(&Mbox_storage_in_2, Config_storage_in_2, Config_storage_in_2->BaseAddress);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XMbox_CfgInitialize %d failed", XPAR_MAILBOX_3_IF_0_DEVICE_ID);
		return XST_FAILURE;
	}

	Config_storage_out_2 = XMbox_LookupConfig(XPAR_MAILBOX_4_IF_0_DEVICE_ID);
	Status = XMbox_CfgInitialize(&Mbox_storage_out_2, Config_storage_out_2, Config_storage_out_2->BaseAddress);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XMbox_CfgInitialize %d failed", XPAR_MAILBOX_4_IF_0_DEVICE_ID);
		return XST_FAILURE;
	}

	XMbox_SetSendThreshold(&Mbox_storage_cmd_in, MAILBOX_DEFAULT_RX_THRESHOLD);
	XMbox_SetInterruptEnable(&Mbox_CMD_IN, XMB_IX_RTA | XMB_IX_ERR);

	XMbox_SetSendThreshold(&Mbox_storage_cmd_out, 0);
	XMbox_SetInterruptEnable(&Mbox_CMD_OUT, XMB_IX_STA | XMB_IX_ERR);

	XMbox_SetSendThreshold(&Mbox_storage_data_in, MAILBOX_DEFAULT_RX_THRESHOLD_LARGE);
	XMbox_SetInterruptEnable(&Mbox_CMD_IN, XMB_IX_RTA | XMB_IX_ERR);

	XMbox_SetSendThreshold(&Mbox_storage_data_out, 0);
	XMbox_SetInterruptEnable(&Mbox_CMD_OUT, XMB_IX_STA | XMB_IX_ERR);

	XMbox_SetSendThreshold(&Mbox_storage_in_2, MAILBOX_DEFAULT_RX_THRESHOLD);
	XMbox_SetInterruptEnable(&Mbox_CMD_IN, XMB_IX_RTA | XMB_IX_ERR);

	XMbox_SetSendThreshold(&Mbox_storage_out_2, 0);
	XMbox_SetInterruptEnable(&Mbox_CMD_OUT, XMB_IX_STA | XMB_IX_ERR);

	/* OctopOS mailbox maps must be initialized before setting up interrupts. */
	OMboxIds_init();

	/* Initialize XIntc */
	Status = XIntc_Initialize(&intc, XPAR_INTC_SINGLE_DEVICE_ID);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Initialize %d failed", XPAR_INTC_SINGLE_DEVICE_ID);
		return XST_FAILURE;
	}

	Xil_ExceptionInit();
	Xil_ExceptionEnable();

	/* Connect interrupts */
	Status = XIntc_Connect(&intc,
			XPAR_MICROBLAZE_4_AXI_INTC_Q_STORAGE_CMD_IN_INTERRUPT_1_INTR,
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*)&Mbox_storage_cmd_in);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed",
				XPAR_MICROBLAZE_4_AXI_INTC_Q_STORAGE_CMD_IN_INTERRUPT_1_INTR);
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
			XPAR_MICROBLAZE_4_AXI_INTC_Q_STORAGE_CMD_OUT_INTERRUPT_1_INTR,
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*)&Mbox_storage_cmd_out);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed",
				XPAR_MICROBLAZE_4_AXI_INTC_Q_STORAGE_CMD_OUT_INTERRUPT_1_INTR);
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
			XPAR_MICROBLAZE_4_AXI_INTC_Q_STORAGE_DATA_OUT_INTERRUPT_FIXED_INTR,
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*)&Mbox_storage_data_out);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed",
				XPAR_MICROBLAZE_4_AXI_INTC_Q_STORAGE_DATA_OUT_INTERRUPT_FIXED_INTR);
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
			XPAR_MICROBLAZE_4_AXI_INTC_Q_STORAGE_DATA_IN_INTERRUPT_FIXED_INTR,
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*)&Mbox_storage_data_in);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed",
				XPAR_MICROBLAZE_4_AXI_INTC_Q_STORAGE_DATA_IN_INTERRUPT_FIXED_INTR);
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
			XPAR_MICROBLAZE_4_AXI_INTC_Q_STORAGE_OUT_2_INTERRUPT_FIXED_INTR,
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*)&Mbox_storage_out_2);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed",
				XPAR_MICROBLAZE_4_AXI_INTC_Q_STORAGE_OUT_2_INTERRUPT_FIXED_INTR);
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
			XPAR_MICROBLAZE_4_AXI_INTC_Q_STORAGE_IN_2_INTERRUPT_FIXED_INTR,
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*)&Mbox_storage_in_2);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed",
				XPAR_MICROBLAZE_4_AXI_INTC_Q_STORAGE_IN_2_INTERRUPT_FIXED_INTR);
		return XST_FAILURE;
	}

	/* Enable and start interrupts */
	XIntc_Enable(&intc, XPAR_MICROBLAZE_4_AXI_INTC_Q_STORAGE_CMD_IN_INTERRUPT_1_INTR);
	XIntc_Enable(&intc, XPAR_MICROBLAZE_4_AXI_INTC_Q_STORAGE_CMD_OUT_INTERRUPT_1_INTR);
	XIntc_Enable(&intc, XPAR_MICROBLAZE_4_AXI_INTC_Q_STORAGE_DATA_OUT_INTERRUPT_FIXED_INTR);
	XIntc_Enable(&intc, XPAR_MICROBLAZE_4_AXI_INTC_Q_STORAGE_DATA_IN_INTERRUPT_FIXED_INTR);
	XIntc_Enable(&intc, XPAR_MICROBLAZE_4_AXI_INTC_Q_STORAGE_OUT_2_INTERRUPT_FIXED_INTR);
	XIntc_Enable(&intc, XPAR_MICROBLAZE_4_AXI_INTC_Q_STORAGE_IN_2_INTERRUPT_FIXED_INTR);

	Status = XIntc_Start(&intc, XIN_REAL_MODE);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Start failed");
		return XST_FAILURE;
	}

	sem_init(&interrupts[Q_STORAGE_DATA_IN], 0, 0);
	sem_init(&interrupts[Q_STORAGE_DATA_OUT], 0, MAILBOX_QUEUE_SIZE_LARGE);
	sem_init(&interrupts[Q_STORAGE_CMD_IN], 0, 0);
	sem_init(&interrupts[Q_STORAGE_CMD_OUT], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_STORAGE_IN_2], 0, 0);
	sem_init(&interrupts[Q_STORAGE_OUT_2], 0, MAILBOX_QUEUE_SIZE);

	initialize_storage_space();

	return XST_SUCCESS;
}

void close_storage(void)
{
}

#endif /* ARCH_SEC_HW_STORAGE */
