#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_fugue.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_hamsi.h"
#include "sha3/sph_panama.h"


//#define DEBUG_ALGO

/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
typedef struct {
	sph_fugue256_context	fugue;
	sph_hamsi256_context	hamsi;
	sph_shavite256_context	shavite;
	sph_panama_context	panama;
} twehash_context_holder;

/* no need to copy, because close reinit the context */
static THREADLOCAL twehash_context_holder ctx;

void init_twe_contexts(void *dummy)
{
	sph_fugue256_init(&ctx.fugue);
	sph_hamsi256_init(&ctx.hamsi);
	sph_shavite256_init(&ctx.shavite);
	sph_panama_init(&ctx.panama);
}

void twehash(void *output, const void *input)
{
	uint32_t hash[16];

	memset(hash, 0, 16 * sizeof(uint32_t));

	sph_fugue256(&ctx.fugue, input, 80);
	sph_fugue256_close(&ctx.fugue, hash);

	sph_shavite256(&ctx.shavite, hash, 64);
	sph_shavite256_close(&ctx.shavite, hash);

	sph_hamsi256(&ctx.hamsi, hash, 64);
	sph_hamsi256_close(&ctx.hamsi, hash);

	sph_panama(&ctx.panama, hash, 64);
	sph_panama_close(&ctx.panama, hash);

	memcpy(output, hash, 32);
}

int scanhash_twe(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
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
		0x10000000
	};
	uint32_t masks[] = {
		0xFFFFFFFF,
		0xFFFFFFF0,
		0xFFFFFF00,
		0xFFFFF000,
		0xFFFF0000,
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
				twehash(hash64, &endiandata);
#ifndef DEBUG_ALGO
				if ((!(hash64[7] & mask)) && fulltest(hash64, ptarget)) {
					*hashes_done = n - first_nonce + 1;
					return true;
				}
#else
				if (!(n % 0x1000) && !thr_id) printf(".");
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
