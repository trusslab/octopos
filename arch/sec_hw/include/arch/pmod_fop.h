/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef __SEC_HW_PMOD_FOPS_H
#define __SEC_HW_PMOD_FOPS_H

#include "PmodSD.h"

void initialize_pmodsd();
DFILE* fop_open(const char *filename, const char *mode);
int fop_close(DFILE *filep);
int fop_seek(DFILE *filep, long int offset, int origin);
size_t fop_read(void *ptr, size_t size, size_t count, DFILE *filep);
size_t fop_write(void *ptr, size_t size, size_t count, DFILE *filep);
size_t fop_size(DFILE *filep);

#endif /* __SEC_HW_PMOD_FOPS_H */