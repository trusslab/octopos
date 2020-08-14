#ifndef OCTOPOS_SEC_HW_SYSCALL_SERIALIZER_H_
#define OCTOPOS_SEC_HW_SYSCALL_SERIALIZER_H_

#define SERIALIZE_16(arg, buf_lr)				\
	{											\
	u16 _arg_local = (u16) arg; 				\
	memcpy(buf_lr, (u16*) &_arg_local, 2);		\
	}

#define SERIALIZE_32(arg, buf_lr)				\
	{											\
	u32 _arg_local = (u32) arg; 				\
	memcpy(buf_lr, (u32*) &_arg_local, 4);		\
	}

#endif /* OCTOPOS_SEC_HW_SYSCALL_SERIALIZER_H_ */
