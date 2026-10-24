/*
 * fec.c -- forward error correction based on Vandermonde matrices
 * 980614
 * (C) 1997-98 Luigi Rizzo (luigi@iet.unipi.it)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#ifndef FEC_VDM_H
#define FEC_VDM_H

#ifndef GF_BITS
#define GF_BITS 8   /* GF(2^GF_BITS), 8-bit gives best performance */
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * fec_new(k, n)  -- allocate a new FEC code descriptor
 *   k : number of source symbols
 *   n : total symbols (k source + (n-k) repair); n-k = P
 * Returns opaque handle; NULL on failure.
 */
void *fec_new(int k, int n);

/*
 * fec_free(code) -- release resources
 */
void fec_free(void *code);

/*
 * fec_encode(code, src, dst, index, sz)
 *   src   : array of k pointers to source symbols (each sz bytes)
 *   dst   : output buffer (sz bytes) for symbol at position `index`
 *   index : 0..k-1 → copy source; k..n-1 → compute repair
 *   sz    : bytes per symbol
 */
void fec_encode(void *code, void *src[], void *dst, int index, int sz);

/*
 * fec_decode(code, pkt, index, sz)
 *   pkt   : array of k pointers to received symbols (modified in-place)
 *   index : array of k received symbol indices (modified in-place)
 *           0..k-1 = source, k..n-1 = repair
 *   sz    : bytes per symbol
 * Returns 0 on success.
 * After decode, pkt[i] contains source symbol i for all i in 0..k-1.
 */
int fec_decode(void *code, void *pkt[], int index[], int sz);

#ifdef __cplusplus
}
#endif

#endif /* FEC_VDM_H */
