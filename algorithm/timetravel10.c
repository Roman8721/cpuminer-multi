#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"

extern uint32_t permutations[];

/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
typedef struct {
	sph_blake512_context	blake;
	sph_bmw512_context	bmw;
	sph_groestl512_context	groestl;
	sph_skein512_context	skein;
	sph_jh512_context	jh;
	sph_keccak512_context	keccak;
	sph_luffa512_context	luffa;
	sph_cubehash512_context	cubehash;
	sph_shavite512_context	shavite;
	sph_simd512_context	simd;
} timetravel10hash_context_holder;

/* no need to copy, because close reinit the context */
static THREADLOCAL timetravel10hash_context_holder ctx;

void init_timetravel10_contexts(void *dummy)
{
	sph_blake512_init(&ctx.blake);
	sph_bmw512_init(&ctx.bmw);
	sph_groestl512_init(&ctx.groestl);
	sph_skein512_init(&ctx.skein);
	sph_jh512_init(&ctx.jh);
	sph_keccak512_init(&ctx.keccak);
	sph_luffa512_init(&ctx.luffa);
	sph_cubehash512_init(&ctx.cubehash);
	sph_shavite512_init(&ctx.shavite);
	sph_simd512_init(&ctx.simd);
}


#define HASH_FUNC_BASE_TIMESTAMP 1492973331 // BitCore: Genesis Timestamp
#define HASH_FUNC_COUNT 10                  // BitCore: HASH_FUNC_COUNT of 11
#define HASH_FUNC_COUNT_PERMUTATIONS 40320  // BitCore: HASH_FUNC_COUNT! 

void timetravel10hash(void *output, const void *input)
{
	uint32_t hash[16], i;
	uint32_t time = ((uint32_t *)input)[17];
	uint32_t permutation = permutations[(time - HASH_FUNC_BASE_TIMESTAMP) % HASH_FUNC_COUNT_PERMUTATIONS];

	memset(hash, 0, 16 * sizeof(uint32_t));

	sph_blake512(&ctx.blake, input, 80);
	sph_blake512_close(&ctx.blake, hash);

	sph_bmw512(&ctx.bmw, hash, 64);
	sph_bmw512_close(&ctx.bmw, hash);

	for (i = 0; i < (4 * (HASH_FUNC_COUNT-2)); i += 4) {
		switch ((permutation >> i) & 0xf) {

			case 0:
				sph_groestl512(&ctx.groestl, hash, 64);
				sph_groestl512_close(&ctx.groestl, hash);
				break;

			case 1:
				sph_skein512(&ctx.skein, hash, 64);
				sph_skein512_close(&ctx.skein, hash);
				break;

			case 2:
				sph_jh512(&ctx.jh, hash, 64);
				sph_jh512_close(&ctx.jh, hash);
				break;

			case 3:
				sph_keccak512(&ctx.keccak, hash, 64);
				sph_keccak512_close(&ctx.keccak, hash);
				break;

			case 4:
				sph_luffa512(&ctx.luffa, hash, 64);
				sph_luffa512_close(&ctx.luffa, hash);
				break;

			case 5:
				sph_cubehash512(&ctx.cubehash, hash, 64);
				sph_cubehash512_close(&ctx.cubehash, hash);
				break;

			case 6:
				sph_shavite512(&ctx.shavite, hash, 64);
				sph_shavite512_close(&ctx.shavite, hash);
				break;

			case 7:
				sph_simd512(&ctx.simd, hash, 64);
				sph_simd512_close(&ctx.simd, hash);
				break;
		}
	}

	memcpy(output, hash, 32);
}

int scanhash_timetravel10(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
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
				timetravel10hash(hash64, &endiandata);
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
