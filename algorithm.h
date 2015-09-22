#ifndef ALGORITHM_H
#define ALGORITHM_H

#include <inttypes.h>
#include <stdbool.h>

#define SCANHASH(name) \
extern int scanhash_ ## name(int thr_id, uint32_t *pdata, const uint32_t *ptarget, \
                            uint32_t max_nonce, uint64_t *hashes_done); \
extern void name ## hash(void* output, const void* input); \
extern void init_ ## name ## _contexts(); \
extern void free_ ## name ## _contexts();

typedef enum {
    ALGO_UNK,
    ALGO_SCRYPT,      /* scrypt(1024,1,1) */
    ALGO_SHA256D,     /* SHA-256d */
    ALGO_DCRYPT,      /* dcrypt */
    ALGO_YESCRYPT,    /* yescypt */
    ALGO_KECCAK,      /* Keccak */
    ALGO_TWE,         /* TweCoin */
    ALGO_HEAVY,       /* Heavy */
    ALGO_QUARK,       /* Quark */
    ALGO_QUBIT,       /* Qubit */
    ALGO_GROESTL,     /* Groestl */
    ALGO_MYRGROESTL,  /* Myriadcoin-groestl */
    ALGO_SKEIN,       /* Skein */
    ALGO_SKEIN2,      /* Woodcoin */
    ALGO_S3,          /* S3 */
    ALGO_NIST5,       /* Nist5 */
    ALGO_SHAVITE3,    /* Shavite3 */
    ALGO_BLAKE,       /* Blake */
    ALGO_FRESH,       /* Fresh */
    ALGO_LBRY,        /* lbrycr */
    ALGO_X11,         /* X11 */
    ALGO_X13,         /* X13 */
    ALGO_X14,         /* X14 */
    ALGO_X15,         /* X15 Whirlpool */
    ALGO_LYRA2RE,     /* Lyra2RE */
    ALGO_PLUCK,       /* Pluck */
    ALGO_PENTABLAKE,  /* Pentablake */
    ALGO_AXIOM,       /* AxiomHash */
    ALGO_CRYPTONIGHT, /* CryptoNight */
    ALGO_WHIRL,       /* Whirlcoin */
    ALGO_WHIRLPOOLX,  /* WhirlpoolX */
} algorithm_type_t;

SCANHASH(sha256d);
SCANHASH(scrypt);
SCANHASH(dcrypt);
SCANHASH(yescrypt);
SCANHASH(keccak);
SCANHASH(twe);
SCANHASH(heavy);
SCANHASH(quark);
SCANHASH(qubit);
SCANHASH(skein);
SCANHASH(skein2);
SCANHASH(s3);
SCANHASH(nist5);
SCANHASH(ink);
SCANHASH(blake);
SCANHASH(fresh);
SCANHASH(lbry);
SCANHASH(x11);
SCANHASH(x13);
SCANHASH(x14);
SCANHASH(x15);
SCANHASH(lyra);
SCANHASH(pluck);
SCANHASH(groestl);
SCANHASH(myriadcoin_groestl);
SCANHASH(pentablake);
SCANHASH(axiom);
SCANHASH(cryptonight);
SCANHASH(whirlcoin);
SCANHASH(whirlpoolx);

typedef struct _algorithm_t {
    const char* name; /* Human-readable identifier */
    algorithm_type_t type; //algorithm type
    char *displayname;
//    int64_t max;
    void (*gen_hash)(unsigned char *hash, const unsigned char *data, int len);
    void (*gen_hash2)(unsigned char *hash, const unsigned char *data, int len);
    int (*scanhash)(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                    uint32_t max_nonce, uint64_t *hashes_done);
    void (*simplehash)(void *output, const void *input);
    void (*init_contexts)(void *params);
    void (*free_contexts)(void *params);
} algorithm_t;

#endif /* ALGORITHM_H */

