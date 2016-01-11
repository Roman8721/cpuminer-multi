/*
	scrypt-jane by Andrew M, https://github.com/floodyberry/scrypt-jane

	Public Domain or MIT License, whichever is easier
*/

#ifndef SCRYPTJANE_H
#define SCRYPTJANE_H

typedef struct scrypt_aligned_alloc_t {
	uint8_t *mem, *ptr;
} scrypt_aligned_alloc;

scrypt_aligned_alloc scrypt_alloc(uint64_t size);
void scrypt_free(scrypt_aligned_alloc *aa);

#endif