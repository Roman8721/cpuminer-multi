#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "crypto/mshabal.h"

//#define DEBUG_ALGO

#define _ALIGN(x) __attribute__ ((aligned(x)))

typedef uint32_t hash_t[8];

/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
typedef struct {
	mshabal_context	shabal;
	hash_t *hash1, *hash2, *hash3, *hash4;
} axiomhash_context_holder;

static THREADLOCAL axiomhash_context_holder ctx;

void init_axiom_contexts(void *dummy)
{
	mshabal_init(&ctx.shabal, 256);
	ctx.hash1 = amalloc(128, 65536 * 32);
	ctx.hash2 = amalloc(128, 65536 * 32);
	ctx.hash3 = amalloc(128, 65536 * 32);
	ctx.hash4 = amalloc(128, 65536 * 32);
}

void free_axiom_contexts(void *dummy)
{
	afree(ctx.hash1);
	afree(ctx.hash2);
	afree(ctx.hash3);
	afree(ctx.hash4);
}

void axiomhash(void *output, const void *input)
{
	axiomhash_4way(input, output, input, output, input, output, input, output);
}

void axiomhash_4way(const void *input1, void *output1, const void *input2, void *output2, const void *input3, void *output3, const void *input4, void *output4)
{
	mshabal_context ctx_shabal;
	int i;

	memset(ctx.hash1, 0, 65536 * 32);
	memset(ctx.hash2, 0, 65536 * 32);
	memset(ctx.hash3, 0, 65536 * 32);
	memset(ctx.hash4, 0, 65536 * 32);

	memcpy(&ctx_shabal, &ctx.shabal, sizeof(mshabal_context));
	mshabal(&ctx_shabal, input1, input2, input3, input4, 80);
	mshabal_close(&ctx_shabal, 0, 0, 0, 0, 0, ctx.hash1[0], ctx.hash2[0], ctx.hash3[0], ctx.hash4[0]);

	for(i = 1; i < 65536; i++)
	{
		memcpy(&ctx_shabal, &ctx.shabal, sizeof(mshabal_context));
		mshabal(&ctx_shabal, ctx.hash1[i - 1], ctx.hash2[i - 1], ctx.hash3[i - 1], ctx.hash4[i - 1], 32);
		mshabal_close(&ctx_shabal, 0, 0, 0, 0, 0, ctx.hash1[i], ctx.hash2[i], ctx.hash3[i], ctx.hash4[i]);
	}

	for (int b = 0; b < 65536; b++)
	{
		int p = b > 0 ? b - 1 : 0xffff;
		int q1 = ctx.hash1[p][0] % 0xffff;
		int j1 = (b + q1) % 65536;
		int q2 = ctx.hash2[p][0] % 0xffff;
		int j2 = (b + q2) % 65536;
		int q3 = ctx.hash3[p][0] % 0xffff;
		int j3 = (b + q3) % 65536;
		int q4 = ctx.hash4[p][0] % 0xffff;
		int j4 = (b + q4) % 65536;

		memcpy(&ctx_shabal, &ctx.shabal, sizeof(mshabal_context));
		mshabal(&ctx_shabal, ctx.hash1[p], ctx.hash2[p], ctx.hash3[p], ctx.hash4[p], 32);
		mshabal(&ctx_shabal, ctx.hash1[j1], ctx.hash2[j2], ctx.hash3[j3], ctx.hash4[j4], 32);
		mshabal_close(&ctx_shabal, 0, 0, 0, 0, 0, ctx.hash1[b], ctx.hash2[b], ctx.hash3[b], ctx.hash4[b]);
	}

	memcpy(output1, ctx.hash1[0xffff], 32);
	memcpy(output2, ctx.hash2[0xffff], 32);
	memcpy(output3, ctx.hash3[0xffff], 32);
	memcpy(output4, ctx.hash4[0xffff], 32);
}

int scanhash_axiom(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t n = pdata[19];
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];

	uint32_t _ALIGN(128) hash64_1[8], hash64_2[8], hash64_3[8], hash64_4[8];
	uint32_t _ALIGN(128) endiandata_1[20], endiandata_2[20], endiandata_3[20], endiandata_4[20];

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
	for (int kk=0; kk < 19; kk++) {
		be32enc(&endiandata_1[kk], pdata[kk]);
	}

	memcpy(endiandata_2, endiandata_1, sizeof(endiandata_1));
	memcpy(endiandata_3, endiandata_1, sizeof(endiandata_1));
	memcpy(endiandata_4, endiandata_1, sizeof(endiandata_1));

#ifdef DEBUG_ALGO
	printf("[%d] Htarg=%X\n", thr_id, Htarg);
#endif
	for (int m=0; m < sizeof(masks); m++) {
		if (Htarg <= htmax[m]) {
			uint32_t mask = masks[m];
			do {
				be32enc(&endiandata_1[19], n);
				be32enc(&endiandata_2[19], n + 1);
				be32enc(&endiandata_3[19], n + 2);
				be32enc(&endiandata_4[19], n + 3);
				axiomhash_4way(endiandata_1, hash64_1, endiandata_2, hash64_2, endiandata_3, hash64_3, endiandata_4, hash64_4);

#ifndef DEBUG_ALGO
				if ((!(hash64_1[7] & mask)) && fulltest(hash64_1, ptarget)) {
					*hashes_done = n - first_nonce + 1;
					pdata[19] = n;
					return true;
				}
				if ((!(hash64_2[7] & mask)) && fulltest(hash64_2, ptarget)) {
					*hashes_done = n - first_nonce + 2;
					pdata[19] = n + 1;
					return true;
				}
				if ((!(hash64_3[7] & mask)) && fulltest(hash64_3, ptarget)) {
					*hashes_done = n - first_nonce + 3;
					pdata[19] = n + 2;
					return true;
				}
				if ((!(hash64_4[7] & mask)) && fulltest(hash64_4, ptarget)) {
					*hashes_done = n - first_nonce + 4;
					pdata[19] = n + 3;
					return true;
				}
#else
				if (!(n % 0x100) && !thr_id) printf(".");
				if (!(hash64_1[7] & mask)) {
					printf("[%d]1",thr_id);
					if (fulltest(hash64_1, ptarget)) {
						*hashes_done = n - first_nonce + 1;
						pdata[19] = n;
						return true;
					}
				}
				if (!(hash64_2[7] & mask)) {
					printf("[%d]2",thr_id);
					if (fulltest(hash64_2, ptarget)) {
						*hashes_done = n - first_nonce + 2;
						pdata[19] = n + 1;
						return true;
					}
				}
				if (!(hash64_3[7] & mask)) {
					printf("[%d]3",thr_id);
					if (fulltest(hash64_3, ptarget)) {
						*hashes_done = n - first_nonce + 3;
						pdata[19] = n + 2;
						return true;
					}
				}
				if (!(hash64_4[7] & mask)) {
					printf("[%d]4",thr_id);
					if (fulltest(hash64_4, ptarget)) {
						*hashes_done = n - first_nonce + 4;
						pdata[19] = n + 3;
						return true;
					}
				}
#endif
				n += 4;

			} while (n < max_nonce && !work_restart[thr_id].restart);
			// see blake.c if else to understand the loop on htmax => mask
			break;
		}
	}

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
