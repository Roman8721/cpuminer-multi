#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* Hard-coded scrypt parameteres r and p - mikaelh */
#define SCRYPT_R 1
#define SCRYPT_P 1

#define SCRYPT_SALSA64
#define SCRYPT_SKEIN512
#define SCRYPT_CHOOSE_COMPILETIME

#include "ar2/src/argon2.h"
#include "scrypt-jane.h"
#include "scryptjane/scrypt-jane-portable.h"
#include "scryptjane/scrypt-jane-hash.h"
#include "scryptjane/scrypt-jane-romix.h"
#include "scryptjane/scrypt-jane-test-vectors.h"

void
scrypt(const uint8_t *password, size_t password_len, const uint8_t *salt, size_t salt_len, uint32_t N, uint8_t *out, size_t bytes, uint8_t *X, uint8_t *Y, uint8_t *V, uint32_t r, uint32_t p)
{
	uint32_t chunk_bytes, i;

	chunk_bytes = SCRYPT_BLOCK_BYTES * r * 2;

	scrypt_pbkdf2(password, password_len, salt, salt_len, 1, X, chunk_bytes * p);

	/* 2: X = ROMix(X) */
	for (i = 0; i < p; i++)
		scrypt_ROMix((scrypt_mix_word_t *)(X + (chunk_bytes * i)), (scrypt_mix_word_t *)Y, (scrypt_mix_word_t *)V, N, r);

	/* 3: Out = PBKDF2(password, X) */
	scrypt_pbkdf2(password, password_len, X, chunk_bytes * p, 1, out, bytes);

#ifdef SCRYPT_PREVENT_STATE_LEAK
	scrypt_ensure_zero(YX.ptr, (p + 1) * chunk_bytes);
#endif

}


void argon2_hash(void *output, const void *input, int t_costs, int m_costs, uint32_t N, uint8_t *X, uint8_t *Y, uint8_t *V, uint32_t r, uint32_t p)
{
	// these uint512 in the c++ source of the client are backed by an array of uint32
	uint32_t hashA[8], hashB[8], hashC[8];
	uint32_t mask = 8;
	uint32_t zero = 0;

	scrypt((const unsigned char *)input, 80,
		(const unsigned char *)input, 80,
		N, (unsigned char *)hashA, 32, X, Y, V, r, p);

	if ((hashA[0] & mask) != zero)
		hash_argon2d(hashB, 32, hashA, 32,
			hashA, 32, t_costs, m_costs);
	else
		hash_argon2i(hashB, 32, hashA, 32,
			hashA, 32, t_costs, m_costs);

	scrypt((const unsigned char *)hashB, 32,
		(const unsigned char *)hashB, 32,
		N, (unsigned char *)hashC, 32, X, Y, V, r, p);

	memcpy(output, hashC, 32);

}

void argon2hash(void *output, const void *input)
{
	unsigned int t_costs = 2;
	unsigned int m_costs = 16;
	unsigned int Nfactor = m_costs/2;
	const uint32_t r = SCRYPT_R;
	const uint32_t p = SCRYPT_P;
	scrypt_aligned_alloc YX, V;
	uint8_t *X, *Y;
	uint32_t N, chunk_bytes, i;

	N = (1 << (Nfactor + 1));
	chunk_bytes = SCRYPT_BLOCK_BYTES * r * 2;
	V = scrypt_alloc((uint64_t)N * chunk_bytes);
	YX = scrypt_alloc((p + 1) * chunk_bytes);

	/* 1: X = PBKDF2(password, salt) */
	Y = YX.ptr;
	X = Y + chunk_bytes;

	argon2_hash(output, input, t_costs, m_costs, N, X, Y, V.ptr, p, r);

	scrypt_free(&V);
	scrypt_free(&YX);
}

int scanhash_argon2(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
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
	unsigned int t_costs = 2;
	unsigned int m_costs = 16;
	unsigned int Nfactor = m_costs/2;
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
				pdata[19] = ++n;
				be32enc(&endiandata[19], n);
				argon2_hash(hash64, endiandata, t_costs, m_costs, N, X, Y, V.ptr, p, r);
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
						scrypt_free(&V);
						scrypt_free(&YX);
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
