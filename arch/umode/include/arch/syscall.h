#ifndef OCTOPOS_UMODE_SYSCALL_SERIALIZER_H_
#define OCTOPOS_UMODE_SYSCALL_SERIALIZER_H_


#define SERIALIZE_16(arg, buf_lr)				\
	*((uint16_t *) buf_lr) = arg;				

#define SERIALIZE_32(arg, buf_lr)				\
	*((uint32_t *) buf_lr) = arg;				


#endif /* OCTOPOS_UMODE_SYSCALL_SERIALIZER_H_ */
