/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef OCTOPOS_SEC_HW_SYSCALL_SERIALIZER_H_
#define OCTOPOS_SEC_HW_SYSCALL_SERIALIZER_H_

#ifndef CONFIG_ARM64
#include "xil_types.h"
#endif

#define SERIALIZE_16(arg, buf_lr)				\
	{							\
	u16 _arg_local = (u16) arg; 				\
	memcpy(buf_lr, (u16*) &_arg_local, 2);			\
	}

#define SERIALIZE_32(arg, buf_lr)				\
	{							\
	u32 _arg_local = (u32) arg; 				\
	memcpy(buf_lr, (u32*) &_arg_local, 4);			\
	}

#define DESERIALIZE_16(arg_ptr, buf_lr)				\
	{							\
	memcpy((u16*) arg_ptr, (u16*) buf_lr, 2);		\
	}

#define DESERIALIZE_32(arg_ptr, buf_lr)				\
	{							\
	memcpy((u32*) arg_ptr, (u32*) buf_lr, 4);		\
	}


#endif /* OCTOPOS_SEC_HW_SYSCALL_SERIALIZER_H_ */
