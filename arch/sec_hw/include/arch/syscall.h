#ifndef OCTOPOS_SEC_HW_SYSCALL_SERIALIZER_H_
#define OCTOPOS_SEC_HW_SYSCALL_SERIALIZER_H_

#ifdef ARCH_SEC_HW_OS

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


// #define SERIALIZE_16(arg, buf_lr)				\
// 	{											\
// 	u16 _arg_local = (u16) arg; 				\
// 	*(buf_lr + 0*sizeof(u8)) = (u8) ((_arg_local >> 8) & 0xff);	\
// 	*(buf_lr + 1*sizeof(u8)) = (u8) ((_arg_local >> 0) & 0xff);	\
// 	}

// #define SERIALIZE_32(arg, buf_lr)					\
// 	{												\
// 	u32 _arg_local = (u32) arg; 					\
// 	*(buf_lr + 0*sizeof(u8)) = (u8) ((_arg_local >> 24) & 0xff);	\
// 	*(buf_lr + 1*sizeof(u8)) = (u8) ((_arg_local >> 16) & 0xff);	\
// 	*(buf_lr + 2*sizeof(u8)) = (u8) ((_arg_local >> 8) & 0xff);	\
// 	*(buf_lr + 3*sizeof(u8)) = (u8) ((_arg_local >> 0) & 0xff);	\
// 	}

#else /* ARCH_SEC_HW_OS */

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

#endif /* ARCH_SEC_HW_OS */

#endif /* OCTOPOS_SEC_HW_SYSCALL_SERIALIZER_H_ */
