#ifndef OCTOPOS_UMODE_SYSCALL_SERIALIZER_H_
#define OCTOPOS_UMODE_SYSCALL_SERIALIZER_H_


#define SERIALIZE_16(arg, buf_lr)				\
	*((uint16_t *) buf_lr) = arg;				

#define SERIALIZE_32(arg, buf_lr)				\
	*((uint32_t *) buf_lr) = arg;				

#define DESERIALIZE_16(arg_ptr, buf_lr)				\
	{							\
	*((uint16_t *) arg_ptr) = *((uint16_t *) buf_lr);	\
	}

#define DESERIALIZE_32(arg_ptr, buf_lr)				\
	{							\
	*((uint32_t *) arg_ptr) = *((uint32_t *) buf_lr);	\
	}

#endif /* OCTOPOS_UMODE_SYSCALL_SERIALIZER_H_ */
