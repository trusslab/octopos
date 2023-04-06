/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef __COMPILE_H
#define __COMPILE_H

#undef _inline
#define _inline inline __attribute__((always_inline))

#define containof(ptr, type, member)\
	((type *)((char *)(ptr) - (size_t)&((type *)0)->member))

#endif	/* complie.h */
