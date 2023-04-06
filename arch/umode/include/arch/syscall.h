/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
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
