/*
	scrypt-jane by Andrew M, https://github.com/floodyberry/scrypt-jane

	Public Domain or MIT License, whichever is easier
*/

#include "cpuminer-config.h"
#include "miner.h"

#include <string.h>

/* Hard-coded scrypt parameteres r and p - mikaelh */
#define SCRYPT_R 1
#define SCRYPT_P 1

/* Only the instrinsics versions are optimized for hard-coded values - mikaelh */

#include "scryptjane/scrypt-jane-portable.h"
#include "scryptjane/scrypt-jane-hash.h"
#include "scryptjane/scrypt-jane-romix.h"
#include "scryptjane/scrypt-jane-test-vectors.h"


#define scrypt_maxN 30  /* (1 << (30 + 1)) = ~2 billion */
#if (SCRYPT_BLOCK_BYTES == 64)
#define scrypt_r_32kb 8 /* (1 << 8) = 256 * 2 blocks in a chunk * 64 bytes = Max of 32kb in a chunk */
#elif (SCRYPT_BLOCK_BYTES == 128)
#define scrypt_r_32kb 7 /* (1 << 7) = 128 * 2 blocks in a chunk * 128 bytes = Max of 32kb in a chunk */
#elif (SCRYPT_BLOCK_BYTES == 256)
#define scrypt_r_32kb 6 /* (1 << 6) = 64 * 2 blocks in a chunk * 256 bytes = Max of 32kb in a chunk */
#elif (SCRYPT_BLOCK_BYTES == 512)
#define scrypt_r_32kb 5 /* (1 << 5) = 32 * 2 blocks in a chunk * 512 bytes = Max of 32kb in a chunk */
#endif
#define scrypt_maxr scrypt_r_32kb /* 32kb */
#define scrypt_maxp 25  /* (1 << 25) = ~33 million */

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#ifndef max
inline int max ( int a, int b ) { return a > b ? a : b; }
#endif
#ifndef min
inline int min ( int a, int b ) { return a < b ? a : b; }
#endif

/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
typedef struct {
	int time;
} scrypt_janehash_context_holder;

/* no need to copy, because close reinit the context */
static THREADLOCAL scrypt_janehash_context_holder ctx;

void init_scrypt_jane_contexts(void *dummy)
{
	ctx.time = *(int *)dummy;
}

typedef struct scrypt_aligned_alloc_t {
	uint8_t *mem, *ptr;
} scrypt_aligned_alloc;

static scrypt_aligned_alloc
scrypt_alloc(uint64_t size) {
	static const size_t max_alloc = (size_t)-1;
	scrypt_aligned_alloc aa;
	size += (SCRYPT_BLOCK_BYTES - 1);
	if (size > max_alloc) {
		applog(LOG_ERR, "scrypt-jane: not enough address space on this CPU to allocate required memory");
		exit(1);
	}
	aa.mem = (uint8_t *)malloc((size_t)size);
	aa.ptr = (uint8_t *)(((size_t)aa.mem + (SCRYPT_BLOCK_BYTES - 1)) & ~(SCRYPT_BLOCK_BYTES - 1));
	if (!aa.mem){
		applog(LOG_ERR, "scrypt-jane: out of memory");
		exit(1);
	}
	return aa;
}

static void
scrypt_free(scrypt_aligned_alloc *aa) {
	free(aa->mem);
}

void
scrypt_N_1_1(const uint8_t *password, size_t password_len, const uint8_t *salt, size_t salt_len, uint32_t N, uint8_t *out, size_t bytes, uint8_t *X, uint8_t *Y, uint8_t *V) {
	uint32_t chunk_bytes, i;
	const uint32_t r = SCRYPT_R;
	const uint32_t p = SCRYPT_P;

#if !defined(SCRYPT_CHOOSE_COMPILETIME)
	scrypt_ROMixfn scrypt_ROMix = scrypt_getROMix();
#endif

	chunk_bytes = SCRYPT_BLOCK_BYTES * r * 2;

	/* 1: X = PBKDF2(password, salt) */
	scrypt_pbkdf2_1(password, password_len, salt, salt_len, X, chunk_bytes * p);

	/* 2: X = ROMix(X) */
	for (i = 0; i < p; i++)
		scrypt_ROMix_1((scrypt_mix_word_t *)(X + (chunk_bytes * i)), (scrypt_mix_word_t *)Y, (scrypt_mix_word_t *)V, N);

	/* 3: Out = PBKDF2(password, X) */
	scrypt_pbkdf2_1(password, password_len, X, chunk_bytes * p, out, bytes);

#ifdef SCRYPT_PREVENT_STATE_LEAK
	/* This is an unnecessary security feature - mikaelh */
	scrypt_ensure_zero(Y, (p + 1) * chunk_bytes);
#endif
}


//  increasing Nfactor gradually
const unsigned char minNfactor = 4;
const unsigned char maxNfactor = 30;

unsigned char GetNfactor(unsigned int nTimestamp) {
	int l = 0;

	if (nTimestamp <= ctx.time)
		return minNfactor;

	unsigned long int s = nTimestamp - ctx.time;
	while ((s >> 1) > 3) {
		l += 1;
		s >>= 1;
	}

	s &= 3;

	int n = (l * 170 + s * 25 - 2320) / 100;

	if (n < 0) n = 0;

	if (n > 255) n = 255;

	unsigned char N = (unsigned char)n;
//	printf("GetNfactor: %d -> l:%d s:%d : n:%d / N:%d\n", nTimestamp - 1402845776, l, s, n, min(max(N, minNfactor), maxNfactor));

	if(N < minNfactor) return minNfactor;
	if(N > maxNfactor) return maxNfactor;
	return N;
}

void scrypt_janehash(void *output, const void *input) {
	scrypt_aligned_alloc YX, V;
	uint8_t *X, *Y;
	uint32_t N, chunk_bytes;
	const uint32_t r = SCRYPT_R;
	const uint32_t p = SCRYPT_P;

	int Nfactor = GetNfactor(((uint32_t*)input)[17]);
	if (Nfactor > scrypt_maxN) {
		applog(LOG_ERR, "scrypt-jane: N out of range");
		exit(1);
	}
	N = (1 << (Nfactor + 1));

	chunk_bytes = SCRYPT_BLOCK_BYTES * r * 2;
	V = scrypt_alloc((uint64_t)N * chunk_bytes);
	YX = scrypt_alloc((p + 1) * chunk_bytes);

	Y = YX.ptr;
	X = Y + chunk_bytes;

	scrypt_N_1_1((unsigned char *)input, 80, (unsigned char *)input, 80, N, (unsigned char *)output, 32, X, Y, V.ptr);

	scrypt_free(&V);
	scrypt_free(&YX);
}

int scanhash_scrypt_jane(int thr_id, uint32_t *pdata,
	const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];

	uint32_t hash64[8] __attribute__((aligned(32)));
	uint32_t endiandata[32];

	scrypt_aligned_alloc YX, V;
	uint8_t *X, *Y;
	uint32_t N, chunk_bytes;
	const uint32_t r = SCRYPT_R;
	const uint32_t p = SCRYPT_P;
	int i;

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
		be32enc(&endiandata[kk], (pdata)[kk]);
	};

	int Nfactor = GetNfactor(endiandata[17]);
	if (Nfactor > scrypt_maxN) {
		applog(LOG_ERR, "scrypt-jane: N out of range");
		exit(1);
	}

	N = (1 << (Nfactor + 1));

	chunk_bytes = SCRYPT_BLOCK_BYTES * r * 2;
	V = scrypt_alloc((uint64_t)N * chunk_bytes);
	YX = scrypt_alloc((p + 1) * chunk_bytes);

	Y = YX.ptr;
	X = Y + chunk_bytes;

#ifdef DEBUG_ALGO
	printf("[%d] Htarg=%X\n", thr_id, Htarg);
#endif
	for (int m=0; m < sizeof(masks); m++) {
		if (Htarg <= htmax[m]) {
			uint32_t mask = masks[m];
			do {
				endiandata[19] = ++n;
				scrypt_N_1_1((unsigned char *)endiandata, 80, (unsigned char *)endiandata, 80, N, (unsigned char *)hash64, 32, X, Y, V.ptr);
#ifndef DEBUG_ALGO
				if ((!(hash64[7] & mask)) && fulltest(hash64, ptarget)) {
					*hashes_done = n - first_nonce + 1;
					pdata[19] = n;
					scrypt_free(&V);
					scrypt_free(&YX);
					return 1;
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
			break;
		}
	}

	scrypt_free(&V);
	scrypt_free(&YX);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
