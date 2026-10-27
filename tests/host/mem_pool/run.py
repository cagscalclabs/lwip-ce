#!/usr/bin/env python3
"""Host regression test for src/drivers/mem.c.

Compiles the production allocator with libc malloc/free behind the
platform callbacks and checks:
  * pool (block allocator) first-fit behaviour against a byte-level model,
    including runs that span bitmap bytes;
  * ring push/pop/peek byte content across wraparound, including the
    conditional-subtraction head/tail arithmetic;
  * used-block accounting after every operation.

Run: python3 tests/host/mem_pool/run.py
"""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
source = root / 'src' / 'drivers' / 'mem.c'

PROLOGUE = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define ERROR() ((void)0)
#define ERROR_CODE(x) ((void)0)
static void tls_secure_memzero(void *p, size_t n) { memset(p, 0, n); }
#ifndef SIZE_MAX
#define SIZE_MAX ((size_t)-1)
#endif
/* mem.c only needs the allocator-facing pieces of lwip/opt.h and
 * lwip/logging.h; stub those two headers so the host build stays hermetic. */
#define _LWIP_OPT_H_
#define LWIP_DBG_FILE_ID 0
#define LWIP_DBG_MODULE 0
#define LWIP_DEBUGF(debug, message) ((void)0)
'''

TEST = r'''
/* ---- fast xorshift for reproducible alloc/free patterns ---- */
static uint32_t rng_state = 0x12345678u;
static uint32_t rnd(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

static int failures;

#define CHECK(cond) do { if (!(cond)) { \
    printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

static void *hw_malloc(size_t n) { return malloc(n); }
static void hw_free(void *p) { free(p); }
static void *hw_realloc(void *p, size_t n) { return realloc(p, n); }

/* Byte-level model of the pool bitmap: owned[k] = 1 when block k is used. */
static uint8_t owned[4096];

static void check_pool_model(struct mem_buffer *pool)
{
    uint32_t used = 0;
    for (size_t i = 0; i < pool->u.pool.pool_block_count; i++)
    {
        uint8_t bit = (uint8_t)((pool->u.pool.pool_bitmap[i >> 3] >> (i & 7u)) & 1u);
        CHECK(bit == owned[i]);
        used += bit;
    }
    CHECK(pool->u.pool.pool_used_blocks == used);
}

static void test_pool(void)
{
    /* 64-byte blocks, 4096 bytes => 64 blocks, bitmap spans 8 bytes. */
    struct mem_buffer *pool = mem_buffer_create(MEM_BUFFER_POOL, 4096, 4096, 64,
                                                BUFFER_LOCK_SIZE);
    CHECK(pool != NULL);
    if (!pool)
    {
        return;
    }
    memset(owned, 0, sizeof(owned));

    void *live[64];
    size_t live_blocks[64];
    size_t live_count = 0;

    for (unsigned iter = 0; iter < 4000; iter++)
    {
        uint32_t r = rnd();

        if ((r & 1u) || live_count == 0)
        {
            size_t blocks = 1 + (r >> 8) % 6;
            size_t bytes = blocks * 64 - 1 - (r >> 16) % 3;
            void *p = mem_buffer_malloc(pool, bytes);

            size_t expect_blocks = (bytes + 2 + 63) / 64;
            if (p == NULL)
            {
                /* Model must agree: no such run of free blocks exists. */
                size_t run = 0, best = 0;
                for (size_t i = 0; i < pool->u.pool.pool_block_count; i++)
                {
                    run = owned[i] ? 0 : run + 1;
                    if (run > best) best = run;
                }
                CHECK(best < expect_blocks);
                continue;
            }
            size_t off = (size_t)((uint8_t *)p - pool->buf) - 2;
            CHECK(off % 64 == 0);
            size_t start = off / 64;
            CHECK(start + expect_blocks <= pool->u.pool.pool_block_count);
            /* First-fit invariant: no free run long enough exists before
             * the chosen start. A shorter free run may be skipped. */
            for (size_t s0 = 0; s0 < start; s0++)
            {
                size_t run = 0;
                for (size_t j = s0; j < pool->u.pool.pool_block_count && !owned[j]; j++)
                {
                    run++;
                }
                CHECK(run < expect_blocks);
            }
            for (size_t i = start; i < start + expect_blocks; i++)
            {
                CHECK(!owned[i]);
                owned[i] = 1;
            }
            CHECK(*(uint16_t *)((uint8_t *)p - 2) == expect_blocks);
            live[live_count] = p;
            live_blocks[live_count] = start;
            live_count++;
        }
        else
        {
            size_t idx = (r >> 8) % live_count;
            void *p = live[idx];
            size_t start = live_blocks[idx];
            uint16_t blocks = *(uint16_t *)((uint8_t *)p - 2);
            for (size_t i = start; i < start + blocks; i++)
            {
                owned[i] = 0;
            }
            mem_buffer_free(pool, p);
            live[idx] = live[live_count - 1];
            live_blocks[idx] = live_blocks[live_count - 1];
            live_count--;
        }
        check_pool_model(pool);
    }

    while (live_count)
    {
        live_count--;
        void *p = live[live_count];
        size_t start = live_blocks[live_count];
        uint16_t blocks = *(uint16_t *)((uint8_t *)p - 2);
        for (size_t i = start; i < start + blocks; i++)
        {
            owned[i] = 0;
        }
        mem_buffer_free(pool, p);
    }
    check_pool_model(pool);
    mem_buffer_destroy(pool);
}

static void test_ring(void)
{
    struct mem_buffer *ring = mem_buffer_create(MEM_BUFFER_RING, 256, 256,
                                                256, BUFFER_LOCK_SIZE);
    CHECK(ring != NULL);
    if (!ring)
    {
        return;
    }

    uint8_t model[256];
    size_t mhead = 0, mlen = 0;
    uint8_t in[40], out[40];

    for (unsigned iter = 0; iter < 3000; iter++)
    {
        uint32_t r = rnd();
        if ((r & 1u) || mlen == 255)
        {
            size_t len = 1 + (r >> 8) % 37;
            if (len > 256 - mlen)
            {
                len = 256 - mlen;
            }
            if (len == 0)
            {
                continue;
            }
            for (size_t i = 0; i < len; i++)
            {
                in[i] = (uint8_t)rnd();
            }
            CHECK(mem_buffer_push(ring, in, len));
            for (size_t i = 0; i < len; i++)
            {
                model[(mhead + mlen + i) % 256] = in[i];
            }
            mlen += len;
        }
        else
        {
            size_t len = 1 + (r >> 8) % 37;
            if (len > mlen)
            {
                len = mlen;
            }
            if (len == 0)
            {
                continue;
            }
            CHECK(mem_buffer_pop(ring, out, len) == len);
            for (size_t i = 0; i < len; i++)
            {
                CHECK(out[i] == model[(mhead + i) % 256]);
            }
            mhead = (mhead + len) % 256;
            mlen -= len;
        }
        CHECK(ring->u.ring.len == mlen);
        CHECK(ring->u.ring.head == mhead);
        if (mlen)
        {
            size_t off = (r >> 20) % mlen;
            size_t len = 1 + (r >> 24) % (mlen - off);
            uint8_t peek[256];
            CHECK(mem_buffer_peek(ring, off, peek, len));
            for (size_t i = 0; i < len; i++)
            {
                CHECK(peek[i] == model[(mhead + off + i) % 256]);
            }
        }
    }

    mem_buffer_destroy(ring);
}

int main(void)
{
    if (!mem_init_dynamic(64 * 1024, hw_malloc, hw_free, hw_realloc))
    {
        printf("FAIL mem_init_dynamic\n");
        return 1;
    }
    test_pool();
    test_ring();
    if (failures)
    {
        printf("mem allocator tests FAILED (%d)\n", failures);
        return 1;
    }
    printf("mem allocator tests passed\n");
    return 0;
}
'''


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="mem_pool_") as td:
        src = Path(td) / "test.c"
        exe = Path(td) / "test"
        body = source.read_text()
        body = body.replace('#include "lwip/opt.h"', '')
        body = body.replace('#include "lwip/debug.h"', '')
        body = body.replace('#include "lwip/logging.h"', '')
        src.write_text(PROLOGUE + body + TEST)
        cmd = ["cc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra",
               "-Wno-unused-parameter", "-Wno-unused-variable",
               "-Wno-unused-but-set-variable",
               f"-I{root / 'src'}", f"-I{root / 'src' / 'drivers'}",
               f"-I{root / 'src' / 'include'}", f"-I{root / 'src' / 'tls' / 'includes'}",
               "-DSIZE_MAX=((size_t)-1)", str(src), "-o", str(exe)]
        build = subprocess.run(cmd, capture_output=True, text=True)
        if build.returncode != 0:
            print(build.stdout)
            print(build.stderr)
            return 1
        run = subprocess.run([str(exe)], capture_output=True, text=True)
        print(run.stdout, end="")
        if run.returncode != 0:
            print(run.stderr, end="")
        return run.returncode


if __name__ == "__main__":
    raise SystemExit(main())
