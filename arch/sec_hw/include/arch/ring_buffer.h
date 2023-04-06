/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
// Based on https://github.com/embeddedartistry/embedded-resources/blob/master/examples/c/circular_buffer/circular_buffer.h

#ifndef CIRCULAR_BUFFER_H_
#define CIRCULAR_BUFFER_H_

#include <stdbool.h>

typedef struct circular_buf_t circular_buf_t;

typedef circular_buf_t* cbuf_handle_t;

cbuf_handle_t circular_buf_init(uint32_t* buffer, size_t size);

cbuf_handle_t circular_buf_get_instance(size_t size);

void circular_buf_free(cbuf_handle_t cbuf);

void circular_buf_reset(cbuf_handle_t cbuf);

void circular_buf_put_overwriting(cbuf_handle_t cbuf, uint32_t data);

int circular_buf_put(cbuf_handle_t cbuf, uint32_t data);

int circular_buf_get(cbuf_handle_t cbuf, uint32_t * data);

bool circular_buf_empty(cbuf_handle_t cbuf);

bool circular_buf_full(cbuf_handle_t cbuf);

size_t circular_buf_capacity(cbuf_handle_t cbuf);

size_t circular_buf_size(cbuf_handle_t cbuf);

#endif //CIRCULAR_BUFFER_H_
