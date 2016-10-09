
#include "algorithm.h"
#include "miner.h"

#include <inttypes.h>
#include <string.h>

algorithm_t algos[] = {
    { "scrypt",      ALGO_SCRYPT,     "scrypt(1024, 1, 1)", sha256d, sha256d, scanhash_scrypt, scrypthash, init_scrypt_contexts, NULL },
    { "sha256d",     ALGO_SHA256D,    "SHA-256d", sha256d, sha256d, scanhash_sha256d, NULL, NULL, NULL },
    { "blake",       ALGO_BLAKE,      "Blake", sha256d, sha256d, scanhash_blake, blakehash, init_blake_contexts, NULL },
    { "fresh",       ALGO_FRESH,      "Fresh", sha256d, sha256d, scanhash_fresh, freshhash, init_fresh_contexts, NULL },
    { "lbry",        ALGO_LBRY,       "Lbry", sha256d, sha256d, scanhash_lbry, lbryhash, init_lbry_contexts, NULL },
    { "heavy",       ALGO_HEAVY,      "Heavy", sha256d, sha256d, scanhash_heavy, heavyhash, init_heavy_contexts, NULL },
    { "keccak",      ALGO_KECCAK,     "Keccak", sha256, sha256, scanhash_keccak, keccakhash, init_keccak_contexts, NULL },
    { "shavite3",    ALGO_SHAVITE3,   "Shavite3", sha256d, sha256d, scanhash_ink, inkhash, init_ink_contexts, NULL },
    { "skein",       ALGO_SKEIN,      "Skein", sha256d, sha256d, scanhash_skein, skeinhash, init_skein_contexts, NULL },
    { "quark",       ALGO_QUARK,      "Quark", sha256d, sha256d, scanhash_quark, quarkhash, init_quark_contexts, NULL },
    { "qubit",       ALGO_QUBIT,      "Qubit", sha256d, sha256d, scanhash_qubit, qubithash, init_qubit_contexts, NULL },
    { "pentablake",  ALGO_PENTABLAKE, "pentablake", sha256d, sha256d, scanhash_pentablake, pentablakehash, init_pentablake_contexts, NULL },
    { "axiom",       ALGO_AXIOM,      "AxiomHash", sha256d, sha256d, scanhash_axiom, axiomhash, init_axiom_contexts, NULL },
    { "x11",         ALGO_X11,        "X11", sha256d, sha256d, scanhash_x11, x11hash, init_x11_contexts, NULL },
    { "x13",         ALGO_X13,        "X13", sha256d, sha256d, scanhash_x13, x13hash, init_x13_contexts, NULL },
    { "x14",         ALGO_X14,        "X14", sha256d, sha256d, scanhash_x14, x14hash, init_x14_contexts, NULL },
    { "x15",         ALGO_X15,        "X15", sha256d, sha256d, scanhash_x15, x15hash, init_x15_contexts, NULL },
    { "lyra",        ALGO_LYRA2RE,    "Lyra2RE", sha256d, sha256d, scanhash_lyra, lyrahash, init_lyra_contexts, NULL },
    { "groestl",     ALGO_GROESTL,    "Groestl", sha256, sha256, scanhash_groestl, groestlhash, init_groestl_contexts, NULL },
    { "myr-groestl", ALGO_MYRGROESTL, "Myriadcoin-groestl", sha256, sha256, scanhash_myriadcoin_groestl, myriadcoin_groestlhash, init_myriadcoin_groestl_contexts, NULL },
    { "pluck",       ALGO_PLUCK,      "pluck(128)", sha256d, sha256d, scanhash_pluck, pluckhash, init_pluck_contexts, NULL },
    { "whirlpoolx",  ALGO_WHIRLPOOLX, "WhirlpoolX", sha256d, sha256d, scanhash_whirlpoolx, whirlpoolxhash, init_whirlpoolx_contexts, NULL },

    { "cryptonight", ALGO_CRYPTONIGHT, "cryptonight", sha256d, sha256d, scanhash_cryptonight, NULL, NULL, NULL },

    // Terminator (do not remove)
    { NULL, ALGO_UNK, NULL, NULL, NULL, NULL }
};

