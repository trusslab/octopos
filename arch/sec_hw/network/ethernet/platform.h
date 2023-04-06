/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifdef ARCH_SEC_HW_NETWORK
#ifndef __PLATFORM_H_
#define __PLATFORM_H_
#include "xintc.h"

void platform_setup_interrupts2(XIntc *intcp);
#endif
#endif /* ARCH_SEC_HW_NETWORK */
