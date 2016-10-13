#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "lyra2/Lyra2.h"

//#define DEBUG_ALGO

/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
typedef struct {
    uint32_t height;
} xzchash_context_holder;

/* no need to copy, because close reinit the context */
static THREADLOCAL xzchash_context_holder ctx;

void init_xzc_contexts(void *dummy)
{
    ctx.height = 0;
}
/**
 * Extract bloc height     L H... here len=3, height=0x1333e8
 * "...0000000000ffffffff2703e83313062f503253482f043d61105408"
 */
static uint32_t getblocheight(struct stratum_job *job)
{
    uint32_t height = 0;
    uint8_t hlen = 0, *p, *m;

    // find 0xffff tag
    p = (uint8_t*) job->coinbase + 32;
    m = p + 128;
    while (*p != 0xff && p < m) p++;
    while (*p == 0xff && p < m) p++;
    if (*(p-1) == 0xff && *(p-2) == 0xff) {
        p++; hlen = *p;
        p++; height = le16dec(p);
        p += 2;
        switch (hlen) {
            case 4:
                height += 0x10000UL * le16dec(p);
                break;
            case 3:
                height += 0x10000UL * (*p);
                break;
        }
    }
    return height;
}

void xzc_prepare_work(struct stratum_job *job)
{
    ctx.height = getblocheight(job);
}

void xzchash(void *output, const void *input)
{
	uint32_t hash[16];

	memset(hash, 0, 16 * sizeof(uint32_t));
	LYRA2((void*)hash, 32, input, 80, input, 80, 2, ctx.height, 256, BLOCK_LEN_BLAKE2_SAFE_INT64);

	memcpy(output, hash, 32);
}

int scanhash_xzc(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                    uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];

	uint32_t hash64[8] __attribute__((aligned(32)));
	uint32_t endiandata[32];

	uint64_t htmax[] = {
		0,
		0xF,
		0xFF,
		0xFFF,
		0xFFFF,
		0xFFFFF,
		0xFFFFFF,
		0xFFFFFFF,
		0x10000000
	};
	uint32_t masks[] = {
		0xFFFFFFFF,
		0xFFFFFFF0,
		0xFFFFFF00,
		0xFFFFF000,
		0xFFFF0000,
		0xFFF00000,
		0xFF000000,
		0xF0000000,
		0
	};

	// we need bigendian data...
	for (int kk=0; kk < 32; kk++) {
		be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
	};
#ifdef DEBUG_ALGO
	printf("[%d] Htarg=%X\n", thr_id, Htarg);
#endif
	for (int m=0; m < sizeof(masks); m++) {
		if (Htarg <= htmax[m]) {
			uint32_t mask = masks[m];
			do {
				pdata[19] = ++n;
				be32enc(&endiandata[19], n);
				xzchash(hash64, &endiandata);
#ifndef DEBUG_ALGO
				if ((!(hash64[7] & mask)) && fulltest(hash64, ptarget)) {
					*hashes_done = n - first_nonce + 1;
					return true;
				}
#else
				if (!(n % 0x10) && !thr_id) printf(".\n");
				if (!(hash64[7] & mask)) {
					printf("[%d]",thr_id);
					if (fulltest(hash64, ptarget)) {
						*hashes_done = n - first_nonce + 1;
						return true;
					}
				}
#endif
			} while (n < max_nonce && !work_restart[thr_id].restart);
			// see blake.c if else to understand the loop on htmax => mask
			break;
		}
	}

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
