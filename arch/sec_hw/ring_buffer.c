/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
// Based on https://github.com/embeddedartistry/embedded-resources/blob/master/examples/c/circular_buffer/circular_buffer.c

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>

#include "arch/ring_buffer.h"
#include "arch/sec_hw.h"

struct circular_buf_t {
    uint32_t*   buffer;
    size_t      head;
    size_t      tail;
    size_t      max;
    bool        full;
};

static void advance_pointer(cbuf_handle_t cbuf)
{
    assert(cbuf);

    if(cbuf->full) {
        cbuf->tail = (cbuf->tail + 1) % cbuf->max;
    }

    cbuf->head = (cbuf->head + 1) % cbuf->max;

    // We mark full because we will advance tail on the next time around
    cbuf->full = (cbuf->head == cbuf->tail);
}

static void retreat_pointer(cbuf_handle_t cbuf)
{
    assert(cbuf);

    cbuf->full = false;
    cbuf->tail = (cbuf->tail + 1) % cbuf->max;
}

cbuf_handle_t circular_buf_init(uint32_t* buffer, size_t size)
{
    assert(buffer && size);

    cbuf_handle_t cbuf = (cbuf_handle_t) malloc(sizeof(circular_buf_t));
    assert(cbuf);

    cbuf->buffer = buffer;
    cbuf->max = size;
    circular_buf_reset(cbuf);

    assert(circular_buf_empty(cbuf));

    return cbuf;
}

cbuf_handle_t circular_buf_get_instance(size_t size)
{
    assert(size > 0);

    uint32_t* buf = (uint32_t*) malloc(size * sizeof(uint32_t));
    return circular_buf_init(buf, size);
}

void circular_buf_free(cbuf_handle_t cbuf)
{
    assert(cbuf && cbuf->buffer);
    free(cbuf->buffer);
    free(cbuf);
}

void circular_buf_reset(cbuf_handle_t cbuf)
{
    assert(cbuf);

    cbuf->head = 0;
    cbuf->tail = 0;
    cbuf->full = false;
}

size_t circular_buf_size(cbuf_handle_t cbuf)
{
    assert(cbuf);

    size_t size = cbuf->max;

    if(!cbuf->full) {
        if(cbuf->head >= cbuf->tail)
            size = (cbuf->head - cbuf->tail);
        else
            size = (cbuf->max + cbuf->head - cbuf->tail);
    }

    return size;
}

size_t circular_buf_capacity(cbuf_handle_t cbuf)
{
    assert(cbuf);

    return cbuf->max;
}

void circular_buf_put_overwriting(cbuf_handle_t cbuf, uint32_t data)
{
    assert(cbuf && cbuf->buffer);

    cbuf->buffer[cbuf->head] = data;
    advance_pointer(cbuf);
}

int circular_buf_put(cbuf_handle_t cbuf, uint32_t data)
{
    int r = -1;

    assert(cbuf && cbuf->buffer);

    if(!circular_buf_full(cbuf)) {
        cbuf->buffer[cbuf->head] = data;
        advance_pointer(cbuf);
        r = 0;
    }

    return r;
}

int circular_buf_get(cbuf_handle_t cbuf, uint32_t* data)
{
    assert(cbuf && cbuf->buffer);

    int r = -1;
    if(!circular_buf_empty(cbuf)) {
        *data = cbuf->buffer[cbuf->tail];
        retreat_pointer(cbuf);

        r = 0;
    }

    return r;
}

bool circular_buf_empty(cbuf_handle_t cbuf)
{
    assert(cbuf);

    return (!cbuf->full && (cbuf->head == cbuf->tail));
}

bool circular_buf_full(cbuf_handle_t cbuf)
{
    assert(cbuf);

    return cbuf->full;
}
