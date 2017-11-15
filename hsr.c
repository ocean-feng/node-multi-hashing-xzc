#include "hsr.h"
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
#include "sha3/sph_hamsi.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_sm3.h"


void hsr_hash(const char* input, char* output, uint32_t len)
{
    unsigned char hash[128] = {0}; // uint32_t hashA[16], hashB[16];
    #define hashB hash+64

    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_skein512_context     ctx_skein;
    sph_luffa512_context     ctx_luffa;
    sph_cubehash512_context  ctx_cubehash;
    sph_shavite512_context   ctx_shavite;
    sph_simd512_context      ctx_simd;
    sph_echo512_context      ctx_echo;
    sph_hamsi512_context     ctx_hamsi;
    sph_fugue512_context     ctx_fugue;

    //hsr
    sm3_ctx_t ctx_sm3;

    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, input, 80);
    sph_blake512_close(&ctx_blake, hash);

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hash, 64);
    sph_bmw512_close(&ctx_bmw, hashB);

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, hashB, 64);
    sph_groestl512_close(&ctx_groestl, hash);

    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, hash, 64);
    sph_skein512_close(&ctx_skein, hashB);

    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, hashB, 64);
    sph_jh512_close(&ctx_jh, hash);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, hash, 64);
    sph_keccak512_close(&ctx_keccak, hashB);

    sph_luffa512_init(&ctx_luffa);
    sph_luffa512(&ctx_luffa, hashB, 64);
    sph_luffa512_close(&ctx_luffa, hash);

    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, hash, 64);
    sph_cubehash512_close(&ctx_cubehash, hashB);

    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hashB, 64);
    sph_shavite512_close(&ctx_shavite, hash);

    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, hash, 64);
    sph_simd512_close(&ctx_simd, hashB);

    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hashB, 64);
    sph_echo512_close(&ctx_echo, hash);

    uint32_t sm3_hash[32];
    memset(sm3_hash, 0, sizeof sm3_hash);

    sm3_init(&ctx_sm3);
    sph_sm3(&ctx_sm3, (const void*)hash, 64);
    sph_sm3_close(&ctx_sm3, (void*)sm3_hash);

    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512(&ctx_hamsi, sm3_hash, 64);
    sph_hamsi512_close(&ctx_hamsi, hashB);

    sph_fugue512_init(&ctx_fugue);
    sph_fugue512(&ctx_fugue, hashB, 64);
    sph_fugue512_close(&ctx_fugue, hash);

    memcpy(output, hash, 32);
	
}

