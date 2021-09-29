#include "sleep.h"
#include "stdlib.h"

#include "arch/semaphore.h"
#include "arch/sec_hw.h"
#include "arch/ring_buffer.h"

#include "octopos/mailbox.h"

#include "xil_assert.h"
#include "arch/octopos_xmbox.h"

#ifdef ARCH_SEC_HW_OS
extern OCTOPOS_XMbox Mbox_keyboard;
extern sem_t availables[NUM_QUEUES + 1];
#endif

int sem_init(sem_t *sem, int pshared, int value) 
{
	sem->count = value;
	return 0;
}

int sem_post(sem_t *sem) 
{
	_SEC_HW_ASSERT_NON_VOID(sem->count < 2147483647);
	sem->count += 1;
	return 0;
}

int sem_wait(sem_t *sem) 
{
	if (sem->count <= 0) {
		while(1) {
			if (sem->count > 0) {
				sem -> count -= 1;
				break;
			}
			usleep(1);
		}
	} else {
		sem -> count -= 1;
	}
	return 0;
}

int _sem_retrieve_mailbox_message_blocking_cbuf(OCTOPOS_XMbox *InstancePtr, cbuf_handle_t cbuf)
{
	int			status;
	uint8_t		*message_buffer;

	message_buffer = (uint8_t*) calloc(MAILBOX_QUEUE_MSG_SIZE, sizeof(uint8_t));
	OCTOPOS_XMbox_ReadBlocking(InstancePtr, (u32*)(message_buffer), MAILBOX_QUEUE_MSG_SIZE);

	status = circular_buf_put(cbuf, (uint32_t) message_buffer);

	if (status != XST_SUCCESS) {
		/* since the cpu pulls io, this should never happen */
		_SEC_HW_ERROR("Ring buffer is full. The system may be out of sync.");
		_SEC_HW_ASSERT_NON_VOID(FALSE);
	}

	return 0;
}

int _sem_retrieve_mailbox_message_blocking_buf(OCTOPOS_XMbox *InstancePtr, uint8_t* buf)
{
	OCTOPOS_XMbox_ReadBlocking(InstancePtr, (u32*)(buf), MAILBOX_QUEUE_MSG_SIZE);
	return 0;
}

int _sem_retrieve_mailbox_message_blocking_buf_large(OCTOPOS_XMbox *InstancePtr, uint8_t* buf)
{
	OCTOPOS_XMbox_ReadBlocking(InstancePtr, (u32*)(buf), MAILBOX_QUEUE_MSG_SIZE_LARGE);
	return 0;
}

static uint8_t *sketch_buffer = NULL;
static u32 sketch_buffer_offset = 0;
static OCTOPOS_XMbox *sketch_xmbox_instance = NULL;

/* The calling function must provide a cbuf handle for the message to be written to.
 * InstancePtr must be a valid XMbox base address. The function will return either
 * zero (in case no message is available), otherwise the number of bytes received.
 */
int _sem_retrieve_mailbox_message_cbuf(OCTOPOS_XMbox *InstancePtr, cbuf_handle_t cbuf)
{
	u32			bytes_read;
	int			status;
	uint8_t		*message_buffer;

	message_buffer = (uint8_t*) calloc(MAILBOX_QUEUE_MSG_SIZE, sizeof(uint8_t));

	if (sketch_buffer)
		status = OCTOPOS_XMbox_Read(InstancePtr,
				(u32*)(message_buffer),
				MAILBOX_QUEUE_MSG_SIZE - sketch_buffer_offset,
				&bytes_read);
	else
		status = OCTOPOS_XMbox_Read(InstancePtr,
				(u32*)(message_buffer),
				MAILBOX_QUEUE_MSG_SIZE,
				&bytes_read);

	if (status != XST_SUCCESS) {
		free(message_buffer);
		return 0;
	} else if (bytes_read == 0) {
		free(message_buffer);
		return 0;
	} else if (bytes_read != MAILBOX_QUEUE_MSG_SIZE) {
		_SEC_HW_DEBUG("MBox read only %d bytes, should be %d bytes",
			bytes_read, 
			MAILBOX_QUEUE_MSG_SIZE);
		if (!sketch_buffer) {
			sketch_xmbox_instance = InstancePtr;
			sketch_buffer_offset = bytes_read;
			sketch_buffer = (uint8_t*) calloc(MAILBOX_QUEUE_MSG_SIZE, sizeof(uint8_t));
			memcpy(sketch_buffer, message_buffer, bytes_read);
			return 0;
		} else {
			/* There is already a incomplete message on the sketch_buffer */
			if (bytes_read + sketch_buffer_offset > MAILBOX_QUEUE_MSG_SIZE) {
				_SEC_HW_ERROR("mailbox corrupted: buffer overflow");
				_SEC_HW_ASSERT_NON_VOID(FALSE)
			}
			if (sketch_xmbox_instance == InstancePtr) {
				_SEC_HW_ERROR("mailbox corrupted: inconsistent id");
				_SEC_HW_ASSERT_NON_VOID(FALSE)
			}

			memcpy(sketch_buffer + sketch_buffer_offset, message_buffer, bytes_read);
			if (bytes_read + sketch_buffer_offset == MAILBOX_QUEUE_MSG_SIZE) {
				/* This read completes the message */
				status = circular_buf_put(cbuf, (uint32_t) sketch_buffer);
				if (status != XST_SUCCESS) {
					free(message_buffer);
					_SEC_HW_ERROR("Ring buffer is full. The system may be out of sync.");
					_SEC_HW_ASSERT_NON_VOID(FALSE);
				}
				free(sketch_buffer);
				sketch_buffer = NULL;
				return MAILBOX_QUEUE_MSG_SIZE;
			} else {
				/* The message is still incomplete after this read */
				return 0;
			}
		}
		
	} else {
		status = circular_buf_put(cbuf, (uint32_t) message_buffer);
		if (status != XST_SUCCESS) {
			free(message_buffer);
			_SEC_HW_ERROR("Ring buffer is full. The system may be out of sync.");
			_SEC_HW_ASSERT_NON_VOID(FALSE);
		}
	}
	return bytes_read;

}

/* The calling function must provide a buffer for the message to be written to.
 * InstancePtr must be a valid XMbox base address. The function will return either
 * zero (in case no message is available), otherwise the number of bytes received.
 */
int _sem_retrieve_mailbox_message_buf(OCTOPOS_XMbox *InstancePtr, uint8_t* buf)
{
	u32			bytes_read;
	int			status;

	if (sketch_buffer)
		status = OCTOPOS_XMbox_Read(InstancePtr,
				(u32*)(buf),
				MAILBOX_QUEUE_MSG_SIZE - sketch_buffer_offset,
				&bytes_read);
	else
		status = OCTOPOS_XMbox_Read(InstancePtr,
				(u32*)(buf),
				MAILBOX_QUEUE_MSG_SIZE,
				&bytes_read);

	if (status != XST_SUCCESS) {
		return 0;
	} else if (bytes_read == 0) {
		return 0;
	} else if (bytes_read != MAILBOX_QUEUE_MSG_SIZE) {
		/* Hardware mailbox messages (4 Bytes) are free of sync issue. However, we
		 * are merging many 4 Bytes messages into one MAILBOX_QUEUE_MSG_SIZE message.
		 * We must consider the sync issue when the writer and reader use the queue
		 * at the same time. The reader may read incomplete messages.
		 */
		_SEC_HW_DEBUG("MBox read only %d bytes, should be %d bytes",
			bytes_read, 
			MAILBOX_QUEUE_MSG_SIZE);
		if (!sketch_buffer) {
			sketch_xmbox_instance = InstancePtr;
			sketch_buffer_offset = bytes_read;
			sketch_buffer = (uint8_t*) calloc(MAILBOX_QUEUE_MSG_SIZE, sizeof(uint8_t));
			memcpy(sketch_buffer, buf, bytes_read);
			return 0;
		} else {
			/* There is already a incomplete message on the sketch_buffer */
			if (bytes_read + sketch_buffer_offset > MAILBOX_QUEUE_MSG_SIZE) {
				_SEC_HW_ERROR("mailbox corrupted: buffer overflow");
				_SEC_HW_ASSERT_NON_VOID(FALSE)
			}
			if (sketch_xmbox_instance == InstancePtr) {
				_SEC_HW_ERROR("mailbox corrupted: inconsistent id");
				_SEC_HW_ASSERT_NON_VOID(FALSE)
			}

			memcpy(sketch_buffer + sketch_buffer_offset, buf, bytes_read);
			if (bytes_read + sketch_buffer_offset == MAILBOX_QUEUE_MSG_SIZE) {
				/* This read completes the message */
				memcpy(buf, sketch_buffer, MAILBOX_QUEUE_MSG_SIZE);
				free(sketch_buffer);
				sketch_buffer = NULL;
				return MAILBOX_QUEUE_MSG_SIZE;
			} else {
				/* The message is still incomplete after this read */
				return 0;
			}

		}
	}

	return bytes_read;
}

int _sem_retrieve_mailbox_message_buf_large(OCTOPOS_XMbox *InstancePtr, uint8_t* buf)
{
	u32			bytes_read;
	int			status;

	if (sketch_buffer)
		status = XMbox_Read(InstancePtr,
				(u32*)(buf),
				MAILBOX_QUEUE_MSG_SIZE_LARGE - sketch_buffer_offset,
				&bytes_read);
	else
		status = XMbox_Read(InstancePtr,
				(u32*)(buf),
				MAILBOX_QUEUE_MSG_SIZE_LARGE,
				&bytes_read);

	if (status != XST_SUCCESS) {
		return 0;
	} else if (bytes_read == 0) {
		return 0;
	} else if (bytes_read != MAILBOX_QUEUE_MSG_SIZE_LARGE) {
		/* Hardware mailbox messages (4 Bytes) are free of sync issue. However, we
		 * are merging many 4 Bytes messages into one MAILBOX_QUEUE_MSG_SIZE message.
		 * We must consider the sync issue when the writer and reader use the queue
		 * at the same time. The reader may read incomplete messages.
		 */
		_SEC_HW_DEBUG("MBox read only %d bytes, should be %d bytes",
			bytes_read,
			MAILBOX_QUEUE_MSG_SIZE_LARGE);
		if (!sketch_buffer) {
			sketch_xmbox_instance = InstancePtr;
			sketch_buffer_offset = bytes_read;
			sketch_buffer = (uint8_t*) calloc(MAILBOX_QUEUE_MSG_SIZE_LARGE, sizeof(uint8_t));
			memcpy(sketch_buffer, buf, bytes_read);
			return 0;
		} else {
			/* There is already a incomplete message on the sketch_buffer */
			if (bytes_read + sketch_buffer_offset > MAILBOX_QUEUE_MSG_SIZE_LARGE) {
				_SEC_HW_ERROR("mailbox corrupted: buffer overflow");
				_SEC_HW_ASSERT_NON_VOID(FALSE)
			}
			if (sketch_xmbox_instance == InstancePtr) {
				_SEC_HW_ERROR("mailbox corrupted: inconsistent id");
				_SEC_HW_ASSERT_NON_VOID(FALSE)
			}

			memcpy(sketch_buffer + sketch_buffer_offset, buf, bytes_read);
			if (bytes_read + sketch_buffer_offset == MAILBOX_QUEUE_MSG_SIZE_LARGE) {
				/* This read completes the message */
				memcpy(buf, sketch_buffer, MAILBOX_QUEUE_MSG_SIZE_LARGE);
				free(sketch_buffer);
				sketch_buffer = NULL;
				return MAILBOX_QUEUE_MSG_SIZE_LARGE;
			} else {
				/* The message is still incomplete after this read */
				return 0;
			}

		}
	}

	return bytes_read;
}

int _sem_deliver_mailbox_message_blocking(OCTOPOS_XMbox *InstancePtr, u32* buf)
{
	OCTOPOS_XMbox_WriteBlocking(InstancePtr, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

int _sem_deliver_mailbox_message_blocking_large(OCTOPOS_XMbox *InstancePtr, u32* buf)
{
	OCTOPOS_XMbox_WriteBlocking(InstancePtr, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);

	return 0;
}

int sem_wait_impatient_send(sem_t *sem, OCTOPOS_XMbox *InstancePtr, u32* buf)
{
	if (sem->count <= 0) {
		_sem_deliver_mailbox_message_blocking(InstancePtr, buf);

		if (sem->count > 0) {
			sem->count -= 1;
		}
	} else {
		sem->count -= 1;
		_sem_deliver_mailbox_message_blocking(InstancePtr, buf);
	}
	return 0;
}

int sem_wait_impatient_send_large(sem_t *sem, OCTOPOS_XMbox *InstancePtr, u32* buf)
{
	if (sem->count <= 0) {
		_sem_deliver_mailbox_message_blocking_large(InstancePtr, buf);

		if (sem->count > 0) {
			sem->count -= 1;
		}
	} else {
		sem->count -= 1;
		_sem_deliver_mailbox_message_blocking_large(InstancePtr, buf);
	}
	return 0;
}

int sem_wait_impatient_receive_cbuf(sem_t *sem, OCTOPOS_XMbox *InstancePtr, cbuf_handle_t cbuf)
{
	if (sem->count <= 0) {
		_sem_retrieve_mailbox_message_blocking_cbuf(InstancePtr, cbuf);
		/* There are two conditions:
		* 1. The mailbox really has nothing, someone writes to it
		*    will trigger an interrupt. We need to eat it here.
		* 2. The mailbox is stuck on a stale message. The blocking
		*    read acts like a plumber. Since interrupt has ever been
		*    triggered for this message, no need to -1. */
		if (sem->count > 0) {
			sem->count -= 1;
		}
	} else {
		sem->count -= 1;
		_sem_retrieve_mailbox_message_blocking_cbuf(InstancePtr, cbuf);
	}
	return 0;
}

int sem_wait_impatient_receive_buf(sem_t *sem, OCTOPOS_XMbox *InstancePtr, uint8_t* buf)
{
	if (sem->count <= 0) {
		_sem_retrieve_mailbox_message_blocking_buf(InstancePtr, buf);
		if (sem->count > 0) {
			sem->count -= 1;
		}
	} else {
		sem->count -= 1;
		_sem_retrieve_mailbox_message_blocking_buf(InstancePtr, buf);
	}
	return 0;
}

int sem_wait_impatient_receive_buf_large(sem_t *sem, OCTOPOS_XMbox *InstancePtr, uint8_t* buf)
{
	if (sem->count <= 0) {
		_sem_retrieve_mailbox_message_blocking_buf_large(InstancePtr, buf);
		if (sem->count > 0) {
			sem->count -= 1;
		}
	} else {
		sem->count -= 1;
		_sem_retrieve_mailbox_message_blocking_buf_large(InstancePtr, buf);
	}
	return 0;
}

int sem_wait_one_time_receive_cbuf(sem_t *sem, OCTOPOS_XMbox *InstancePtr, cbuf_handle_t cbuf)
{
	u32 bytes_read;

	if (sem->count <= 0) {
		bytes_read = _sem_retrieve_mailbox_message_cbuf(InstancePtr, cbuf);
		if (bytes_read != 0 && sem->count > 0) {
			sem->count -= 1;
		}
		return bytes_read;
	} else {
		sem->count -= 1;
		_sem_retrieve_mailbox_message_blocking_cbuf(InstancePtr, cbuf);
		return MAILBOX_QUEUE_MSG_SIZE;
	}    
}

int sem_wait_one_time_receive_buf(sem_t *sem, OCTOPOS_XMbox *InstancePtr, uint8_t* buf)
{
	u32 bytes_read;

	if (sem->count <= 0) {
		bytes_read = _sem_retrieve_mailbox_message_buf(InstancePtr, buf);
		if (bytes_read != 0 && sem->count > 0) {
			sem->count -= 1;
		}
		return bytes_read;
	} else {
		sem->count -= 1;
		bytes_read = _sem_retrieve_mailbox_message_buf(InstancePtr, buf);
		return bytes_read;
	}
}

int sem_wait_one_time_receive_buf_large(sem_t *sem, OCTOPOS_XMbox *InstancePtr, uint8_t* buf)
{
	u32 bytes_read;

	if (sem->count <= 0) {
		bytes_read = _sem_retrieve_mailbox_message_buf_large(InstancePtr, buf);
		if (bytes_read != 0 && sem->count > 0) {
			sem->count -= 1;
		}
		return bytes_read;
	} else {
		sem->count -= 1;
		bytes_read = _sem_retrieve_mailbox_message_buf_large(InstancePtr, buf);
		return bytes_read;
	}
}


OCTOPOS_XMbox* sem_wait_impatient_receive_multiple(sem_t *sem, int mb_count, ...)
{
	OCTOPOS_XMbox*			InstancePtr = NULL;
	_Bool			has_new = FALSE;
	uint32_t		args_ptrs[mb_count];

		va_list args;
		va_start(args, mb_count);

		for (int i = 0; i < mb_count; ++i) {
			InstancePtr = va_arg(args, OCTOPOS_XMbox*);
			_SEC_HW_ASSERT_NON_VOID(InstancePtr);

			_SEC_HW_DEBUG("argument index: %d, mailbox: %p", i, InstancePtr);
			args_ptrs[i] = (uint32_t) InstancePtr;
		}

		va_end(args);

		while (!has_new) {
			for (int i = 0; i < mb_count; ++i) {
#ifdef ARCH_SEC_HW_OS
				if ((OCTOPOS_XMbox*) args_ptrs[i] == &Mbox_keyboard &&
						availables[Q_KEYBOARD].count == 0) {
					continue;
				}
#endif
				if (!OCTOPOS_XMbox_IsEmpty((OCTOPOS_XMbox*) args_ptrs[i])) {
					has_new = TRUE;
					_SEC_HW_DEBUG("mailbox %p has new message", InstancePtr);
					InstancePtr = (OCTOPOS_XMbox*) args_ptrs[i];
					break;
				}
			}
		}

		if (sem->count > 0) {
			sem->count -= 1;
		}

		return InstancePtr;
}

int sem_getvalue(sem_t *sem, int *value)
{
	*value = sem->count;
	return 0;
}
