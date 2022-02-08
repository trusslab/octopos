#ifndef OCTOPOS_UMODE_SYSCALL_SERIALIZER_H_
#define OCTOPOS_UMODE_SYSCALL_SERIALIZER_H_

/* FIXME: move these to arch/mailbox.h and get rid of this file.
 * These macros are not used for syscalls only.
 */

#define SERIALIZE_8(arg, buf_lr)				\
	*((uint8_t *) buf_lr) = (uint8_t) arg;				

#define SERIALIZE_16(arg, buf_lr)				\
	*((uint16_t *) buf_lr) = (uint16_t) arg;				

#define SERIALIZE_32(arg, buf_lr)				\
	*((uint32_t *) buf_lr) = (uint32_t) arg;				

#define DESERIALIZE_8(arg_ptr, buf_lr)				\
	{							\
	*((uint8_t *) arg_ptr) = *((uint8_t *) buf_lr);		\
	}

#define DESERIALIZE_16(arg_ptr, buf_lr)				\
	{							\
	*((uint16_t *) arg_ptr) = *((uint16_t *) buf_lr);	\
	}

#define DESERIALIZE_32(arg_ptr, buf_lr)				\
	{							\
	*((uint32_t *) arg_ptr) = *((uint32_t *) buf_lr);	\
	}

#endif /* OCTOPOS_UMODE_SYSCALL_SERIALIZER_H_ */
