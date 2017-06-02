/*-
 * Copyright 2009 Colin Percival, 2011 ArtForz, 2013 Neisklar, 2017 Zcoin Developers
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

#include "lbry.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sha3/sph_sha2.h"
#include "sha3/sph_ripemd.h"

typedef struct {
  sph_sha256_context  sha256;
  sph_sha512_context  sha512;
  sph_ripemd160_context  ripemd;
} lbryhash_context_holder;

void lbry_hash(const void* input, void* output)
{
  uint32_t hashA[16], hashB[16], hashC[16];
  lbryhash_context_holder ctx;

  sph_sha256_init(&ctx.sha256);
  sph_sha512_init(&ctx.sha512);
  sph_ripemd160_init(&ctx.ripemd);

  sph_sha256 (&ctx.sha256, input, 112);
  sph_sha256_close(&ctx.sha256, hashA);

  sph_sha256 (&ctx.sha256, hashA, 32);
  sph_sha256_close(&ctx.sha256, hashA);

  sph_sha512 (&ctx.sha512, hashA, 32);
  sph_sha512_close(&ctx.sha512, hashA);

  sph_ripemd160 (&ctx.ripemd, hashA, 32);
  sph_ripemd160_close(&ctx.ripemd, hashB);

  sph_ripemd160 (&ctx.ripemd, hashA+8, 32);
  sph_ripemd160_close(&ctx.ripemd, hashC);

  sph_sha256 (&ctx.sha256, hashB, 20);
  sph_sha256 (&ctx.sha256, hashC, 20);
  sph_sha256_close(&ctx.sha256, hashA);

  sph_sha256 (&ctx.sha256, hashA, 32);
  sph_sha256_close(&ctx.sha256, hashA);

  memcpy(output, hashA, 32);
}
