#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_groestl.h"
#include "lyra2/Lyra2.h"

//#define DEBUG_ALGO

/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
typedef struct {
	sph_blake256_context	blake;
	sph_keccak256_context	keccak;
	sph_skein256_context	skein;
	sph_groestl256_context	groestl;
} lyrahash_context_holder;

/* no need to copy, because close reinit the context */
static THREADLOCAL lyrahash_context_holder ctx;

void init_lyra_contexts(void *dummy)
{
	sph_blake256_init(&ctx.blake);
	sph_keccak256_init(&ctx.keccak);
	sph_skein256_init(&ctx.skein);
	sph_groestl256_init(&ctx.groestl);
}

void lyrahash(void *output, const void *input)
{
	uint32_t hashA[16], hashB[16];

	memset(hashA, 0, 16 * sizeof(uint32_t));
	memset(hashB, 0, 16 * sizeof(uint32_t));

	sph_blake256 (&ctx.blake, input, 80);
	sph_blake256_close (&ctx.blake, hashA);

	sph_keccak256 (&ctx.keccak,hashA, 32);
	sph_keccak256_close(&ctx.keccak, hashB);

	LYRA2((void*)hashA, 32, (const void*)hashB, 32, (const void*)hashB, 32, 1, 8, 8);

	sph_skein256 (&ctx.skein, hashA, 32);
	sph_skein256_close(&ctx.skein, hashB);

	sph_groestl256 (&ctx.groestl, hashB, 32);
	sph_groestl256_close(&ctx.groestl, hashA);

	memcpy(output, hashA, 32);
}

int scanhash_lyra(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
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
				lyrahash(hash64, &endiandata);
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
