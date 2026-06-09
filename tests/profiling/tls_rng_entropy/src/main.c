#include <fileioc.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ti/getkey.h>
#include <ti/screen.h>

#include "random.h"

#define RNG_CAPTURE_CHUNKS 24u
/* TI AppVar payload max is typically just under 64 KiB. */
#define RNG_CAPTURE_CHUNK_SIZE (48u * 1024u)
#define RNG_CAPTURE_BLOCK 256u
#define RNG_GROUP_COUNT 2u
#define RNG_GROUP_CHUNKS (RNG_CAPTURE_CHUNKS / RNG_GROUP_COUNT)

struct rng_group_cfg
{
    uint8_t xors; /* whitening XOR count */
};

static bool init_rng_with_retries(void)
{
    for (uint8_t i = 0; i < 4; i++)
    {
        if (tls_random_init_entropy())
            return true;
    }
    return false;
}

static bool write_chunk_appvar(uint8_t group_xors,
                               uint8_t chunk_index,
                               uint8_t xor_count,
                               const volatile uint8_t *source,
                               size_t *failed_offset)
{
    char name[9];
    uint8_t handle;
    uint8_t block[RNG_CAPTURE_BLOCK];

    /* R000..R011, R1700..R1711 */
    snprintf(name, sizeof(name), "R%u%02u", (unsigned int)group_xors, (unsigned int)chunk_index);

    /* replace existing var cleanly */
    (void)ti_Delete(name);

    handle = ti_Open(name, "w");
    if (!handle)
        return false;

    for (size_t off = 0; off < RNG_CAPTURE_CHUNK_SIZE; off += sizeof(block))
    {
        for (size_t i = 0; i < sizeof(block); i++)
        {
            uint8_t v = source[0];
            for (uint8_t j = 0; j < xor_count; j++)
                v ^= source[0];
            block[i] = v;
        }

        if (ti_Write(block, sizeof(block), 1, handle) != 1)
        {
            if (failed_offset)
                *failed_offset = off;
            ti_Close(handle);
            return false;
        }
    }

    if (!ti_SetArchiveStatus(true, handle))
    {
        if (failed_offset)
            *failed_offset = RNG_CAPTURE_CHUNK_SIZE;
        ti_Close(handle);
        return false;
    }

    ti_Close(handle);
    return true;
}

int main(void)
{
    static const struct rng_group_cfg groups[RNG_GROUP_COUNT] = {
        {0u},
        {17u},
    };

    os_ClrHome();
    printf("RNG entropy capture\n");

    if (!init_rng_with_retries())
    {
        printf("init failed\n");
        os_GetKey();
        return 1;
    }

    const volatile uint8_t *source = (const volatile uint8_t *)tls_random_debug_source_ptr();
    if (!source)
    {
        printf("source ptr null\n");
        os_GetKey();
        return 1;
    }

    printf("src=%06lX\n", (unsigned long)(uintptr_t)source);

    for (uint8_t g = 0; g < RNG_GROUP_COUNT; g++)
    {
        printf("group R%u (xor=%u)\n", (unsigned int)groups[g].xors, (unsigned int)groups[g].xors);

        for (uint8_t i = 0; i < RNG_GROUP_CHUNKS; i++)
        {
            size_t failed_offset = 0;
            if (!write_chunk_appvar(groups[g].xors, i, groups[g].xors, source, &failed_offset))
            {
                printf("write fail R%u%02u\n", (unsigned int)groups[g].xors, (unsigned int)i);
                printf("offset %lu\n", (unsigned long)failed_offset);
                os_GetKey();
                return 1;
            }
        }
    }

    printf("done (%u vars)\n", (unsigned int)RNG_CAPTURE_CHUNKS);
    os_GetKey();
    return 0;
}
