/*
 * fec-vdm.c -- forward error correction based on Vandermonde matrices
 * Adapted from Luigi Rizzo's fec.c (1997-98), (C) luigi@iet.unipi.it
 * BSD-licensed. See fec-vdm.h for copyright notice.
 *
 * Changes from original:
 *   - u_long → unsigned long
 *   - bcopy/bzero/bcmp → memcpy/memset/memcmp
 *   - TEST/DEBUG blocks removed
 *   - init_fec() made non-static (matches header declaration)
 *   - gf type declarations consolidated
 */

#ifndef GF_BITS
#define GF_BITS 8
#endif

#include "fec-vdm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if (GF_BITS < 2 || GF_BITS > 16)
#error "GF_BITS must be 2..16"
#endif

#if (GF_BITS <= 8)
typedef unsigned char gf;
#else
typedef unsigned short gf;
#endif

#define GF_SIZE ((1 << GF_BITS) - 1)

static const char *allPp[] = {
    NULL, NULL,
    "111", "1101", "11001", "101001", "1100001", "10010001",
    "101110001", "1000100001", "10010000001", "101000000001",
    "1100101000001", "11011000000001", "110000100010001",
    "1100000000000001", "11010000000010001"
};

static gf gf_exp[2 * GF_SIZE];
static int gf_log[GF_SIZE + 1];
static gf  inverse_table[GF_SIZE + 1];

static inline gf modnn(int x)
{
    while (x >= GF_SIZE) { x -= GF_SIZE; x = (x >> GF_BITS) + (x & GF_SIZE); }
    return (gf)x;
}

#define SWAP(a, b, t) do { t _tmp = (a); (a) = (b); (b) = _tmp; } while (0)

/* ---- GF multiplication ---- */
#if (GF_BITS <= 8)
static gf gf_mul_table[GF_SIZE + 1][GF_SIZE + 1];
#define gf_mul(x, y) gf_mul_table[(x)][(y)]
#define USE_GF_MULC    gf *__gf_mulc_
#define GF_MULC0(c)    __gf_mulc_ = gf_mul_table[(c)]
#define GF_ADDMULC(dst, x) (dst) ^= __gf_mulc_[(x)]

static void init_mul_table(void)
{
    int i, j;
    for (i = 0; i <= GF_SIZE; i++)
        for (j = 0; j <= GF_SIZE; j++)
            gf_mul_table[i][j] = gf_exp[modnn(gf_log[i] + gf_log[j])];
    for (j = 0; j <= GF_SIZE; j++)
        gf_mul_table[0][j] = gf_mul_table[j][0] = 0;
}
#else
static gf gf_mul(gf x, gf y)
{
    if (x == 0 || y == 0) return 0;
    return gf_exp[gf_log[x] + gf_log[y]];
}
#define init_mul_table() do {} while (0)
#define USE_GF_MULC    gf *__gf_mulc_
#define GF_MULC0(c)    __gf_mulc_ = &gf_exp[gf_log[(c)]]
#define GF_ADDMULC(dst, x) do { if (x) (dst) ^= __gf_mulc_[gf_log[(x)]]; } while (0)
#endif

/* ---- helpers ---- */
static void *xmalloc(size_t sz, const char *tag)
{
    void *p = malloc(sz);
    if (!p) { fprintf(stderr, "fec-vdm: malloc failed (%s)\n", tag); exit(1); }
    return p;
}
#define NEW_GF_MAT(r, c) ((gf *)xmalloc((size_t)(r) * (c) * sizeof(gf), "gf_mat"))

static void generate_gf(void)
{
    int i;
    gf mask = 1;
    const char *Pp = allPp[GF_BITS];

    gf_exp[GF_BITS] = 0;
    for (i = 0; i < GF_BITS; i++, mask = (gf)(mask << 1)) {
        gf_exp[i] = mask;
        gf_log[gf_exp[i]] = i;
        if (Pp[i] == '1') gf_exp[GF_BITS] ^= mask;
    }
    gf_log[gf_exp[GF_BITS]] = GF_BITS;
    mask = (gf)(1 << (GF_BITS - 1));
    for (i = GF_BITS + 1; i < GF_SIZE; i++) {
        gf_exp[i] = (gf_exp[i-1] >= mask)
            ? gf_exp[GF_BITS] ^ (gf)((gf_exp[i-1] ^ mask) << 1)
            : (gf)(gf_exp[i-1] << 1);
        gf_log[gf_exp[i]] = i;
    }
    gf_log[0] = GF_SIZE;
    for (i = 0; i < GF_SIZE; i++) gf_exp[i + GF_SIZE] = gf_exp[i];
    inverse_table[0] = 0; inverse_table[1] = 1;
    for (i = 2; i <= GF_SIZE; i++) inverse_table[i] = gf_exp[GF_SIZE - gf_log[i]];
}

/* addmul: dst[] ^= c * src[], loop unrolled x16 */
#define addmul(dst, src, c, sz) do { if ((c) != 0) addmul1((dst),(src),(c),(sz)); } while (0)
#define UNROLL 16
static void addmul1(gf *dst, gf *src, gf c, int sz)
{
    USE_GF_MULC;
    gf *lim = dst + sz - UNROLL + 1;
    GF_MULC0(c);
    for (; dst < lim; dst += UNROLL, src += UNROLL) {
        GF_ADDMULC(dst[0],  src[0]);  GF_ADDMULC(dst[1],  src[1]);
        GF_ADDMULC(dst[2],  src[2]);  GF_ADDMULC(dst[3],  src[3]);
        GF_ADDMULC(dst[4],  src[4]);  GF_ADDMULC(dst[5],  src[5]);
        GF_ADDMULC(dst[6],  src[6]);  GF_ADDMULC(dst[7],  src[7]);
        GF_ADDMULC(dst[8],  src[8]);  GF_ADDMULC(dst[9],  src[9]);
        GF_ADDMULC(dst[10], src[10]); GF_ADDMULC(dst[11], src[11]);
        GF_ADDMULC(dst[12], src[12]); GF_ADDMULC(dst[13], src[13]);
        GF_ADDMULC(dst[14], src[14]); GF_ADDMULC(dst[15], src[15]);
    }
    lim += UNROLL - 1;
    for (; dst < lim; dst++, src++) GF_ADDMULC(*dst, *src);
}

static void matmul(gf *a, gf *b, gf *c, int n, int k, int m)
{
    int row, col, i;
    for (row = 0; row < n; row++)
        for (col = 0; col < m; col++) {
            gf *pa = &a[row * k], *pb = &b[col], acc = 0;
            for (i = 0; i < k; i++, pa++, pb += m) acc ^= gf_mul(*pa, *pb);
            c[row * m + col] = acc;
        }
}

static int invert_mat(gf *src, int k)
{
    int irow = 0, icol = 0, row, col, i, ix;
    int error = 1;
    int *indxc = (int *)xmalloc(k * sizeof(int), "indxc");
    int *indxr = (int *)xmalloc(k * sizeof(int), "indxr");
    int *ipiv  = (int *)xmalloc(k * sizeof(int), "ipiv");
    gf  *id_row   = NEW_GF_MAT(1, k);
    gf  *temp_row = NEW_GF_MAT(1, k);

    (void)temp_row; /* unused but kept for symmetry with original */
    memset(id_row, 0, (size_t)k * sizeof(gf));
    for (i = 0; i < k; i++) ipiv[i] = 0;

    for (col = 0; col < k; col++) {
        irow = icol = -1;
        if (ipiv[col] != 1 && src[col * k + col] != 0) { irow = col; icol = col; goto found_piv; }
        for (row = 0; row < k; row++) {
            if (ipiv[row] == 1) continue;
            for (ix = 0; ix < k; ix++) {
                if (ipiv[ix] == 0 && src[row * k + ix] != 0) { irow = row; icol = ix; goto found_piv; }
                else if (ipiv[ix] > 1) { fprintf(stderr, "fec-vdm: singular matrix\n"); goto fail; }
            }
        }
        if (icol == -1) { fprintf(stderr, "fec-vdm: pivot not found\n"); goto fail; }
found_piv:
        ++(ipiv[icol]);
        if (irow != icol)
            for (ix = 0; ix < k; ix++) SWAP(src[irow * k + ix], src[icol * k + ix], gf);
        indxr[col] = irow; indxc[col] = icol;
        {
            gf *pivot_row = &src[icol * k];
            gf  c = pivot_row[icol];
            if (c == 0) { fprintf(stderr, "fec-vdm: singular matrix 2\n"); goto fail; }
            if (c != 1) {
                c = inverse_table[c]; pivot_row[icol] = 1;
                for (ix = 0; ix < k; ix++) pivot_row[ix] = gf_mul(c, pivot_row[ix]);
            }
            id_row[icol] = 1;
            if (memcmp(pivot_row, id_row, (size_t)k * sizeof(gf)) != 0) {
                gf *pp;
                for (pp = src, ix = 0; ix < k; ix++, pp += k) {
                    if (ix != icol) { gf cv = pp[icol]; pp[icol] = 0; addmul(pp, pivot_row, cv, k); }
                }
            }
            id_row[icol] = 0;
        }
    }
    for (col = k - 1; col >= 0; col--)
        if (indxr[col] != indxc[col])
            for (row = 0; row < k; row++)
                SWAP(src[row * k + indxr[col]], src[row * k + indxc[col]], gf);
    error = 0;
fail:
    free(indxc); free(indxr); free(ipiv); free(id_row); free(temp_row);
    return error;
}

static __attribute__((noinline)) int invert_vdm(gf *src, int k)
{
    int i, j, row, col;
    gf *b, *c, *p;
    gf t, xx;

    if (k == 1) return 0;
    c = NEW_GF_MAT(1, k);
    b = NEW_GF_MAT(1, k);
    p = NEW_GF_MAT(1, k);

    for (j = 1, i = 0; i < k; i++, j += k) { c[i] = 0; p[i] = src[j]; }
    c[k - 1] = p[0];
    for (i = 1; i < k; i++) {
        gf p_i = p[i];
        for (j = k - 1 - (i - 1); j < k - 1; j++) c[j] ^= gf_mul(p_i, c[j + 1]);
        c[k - 1] ^= p_i;
    }
    for (row = 0; row < k; row++) {
        xx = p[row]; t = 1; b[k - 1] = 1;
        for (i = k - 2; i >= 0; i--) {
            b[i] = c[i + 1] ^ gf_mul(xx, b[i + 1]);
            t = gf_mul(xx, t) ^ b[i];
        }
        for (col = 0; col < k; col++) src[col * k + row] = gf_mul(inverse_table[t], b[col]);
    }
    free(c); free(b); free(p);
    return 0;
}

/* ---- public API ---- */

static int fec_initialized = 0;

#define FEC_MAGIC 0xFECC0DECUL

struct fec_parms {
    unsigned long magic;
    int k, n;
    gf *enc_matrix;
};

void fec_free(void *vp)
{
    struct fec_parms *p = (struct fec_parms *)vp;
    if (!p) return;
    free(p->enc_matrix);
    free(p);
}

void *fec_new(int k, int n)
{
    int col, row;
    gf *tmp_m, *walk;
    struct fec_parms *retval;

    if (!fec_initialized) {
        generate_gf();
        init_mul_table();
        fec_initialized = 1;
    }
    if (k > GF_SIZE + 1 || n > GF_SIZE + 1 || k > n) {
        fprintf(stderr, "fec_new: invalid k=%d n=%d (max %d)\n", k, n, GF_SIZE + 1);
        return NULL;
    }
    retval = (struct fec_parms *)xmalloc(sizeof(struct fec_parms), "fec_parms");
    retval->k = k; retval->n = n;
    retval->enc_matrix = NEW_GF_MAT(n, k);
    retval->magic = FEC_MAGIC ^ (unsigned long)k ^ (unsigned long)n;

    tmp_m = NEW_GF_MAT(n, k);
    /* Vandermonde matrix: row 0 = [1,0,0,...], row i>0: p[col] = alpha^(i*col) */
    tmp_m[0] = 1;
    for (col = 1; col < k; col++) tmp_m[col] = 0;
    walk = tmp_m + k;
    for (row = 0; row < n - 1; row++, walk += k)
        for (col = 0; col < k; col++)
            walk[col] = gf_exp[modnn(row * col)];

    /* Build systematic matrix: invert top k×k block, multiply onto parity rows */
    invert_vdm(tmp_m, k);
    matmul(tmp_m + k * k, tmp_m, retval->enc_matrix + k * k, n - k, k, k);
    /* Top k×k block becomes identity */
    memset(retval->enc_matrix, 0, (size_t)k * k * sizeof(gf));
    walk = retval->enc_matrix;
    for (col = 0; col < k; col++, walk += k + 1) *walk = 1;

    free(tmp_m);
    return retval;
}

void fec_encode(void *vcode, void *vsrc[], void *vdst, int index, int sz)
{
    struct fec_parms *code = (struct fec_parms *)vcode;
    gf **src = (gf **)vsrc, *dst = (gf *)vdst;
    int i, k = code->k;
    gf *row_ptr;

    if (index < k) { memcpy(dst, src[index], (size_t)sz * sizeof(gf)); return; }
    if (index < code->n) {
        row_ptr = &code->enc_matrix[index * k];
        memset(dst, 0, (size_t)sz * sizeof(gf));
        for (i = 0; i < k; i++) addmul(dst, src[i], row_ptr[i], sz);
    } else {
        fprintf(stderr, "fec_encode: invalid index %d (max %d)\n", index, code->n - 1);
    }
}

static int shuffle(gf *pkt[], int index[], int k)
{
    int i;
    for (i = 0; i < k; ) {
        int c = index[i];
        if (c >= k || c == i) { i++; continue; }
        if (index[c] == c) return 1; /* conflict */
        SWAP(index[i], index[c], int);
        SWAP(pkt[i],   pkt[c],   gf *);
    }
    return 0;
}

static gf *build_decode_matrix(struct fec_parms *code, gf *pkt[], int index[])
{
    int i, k = code->k;
    gf *row, *matrix = NEW_GF_MAT(k, k);
    (void)pkt;
    for (i = 0, row = matrix; i < k; i++, row += k) {
        if (index[i] < k) {
            memset(row, 0, (size_t)k * sizeof(gf));
            row[i] = 1;
        } else if (index[i] < code->n) {
            memcpy(row, &code->enc_matrix[index[i] * k], (size_t)k * sizeof(gf));
        } else {
            free(matrix); return NULL;
        }
    }
    if (invert_mat(matrix, k)) { free(matrix); return NULL; }
    return matrix;
}

int fec_decode(void *vcode, void *vpkt[], int index[], int sz)
{
    struct fec_parms *code = (struct fec_parms *)vcode;
    gf **pkt = (gf **)vpkt;
    gf *m_dec, **new_pkt;
    int row, col, k = code->k;

    if (shuffle(pkt, index, k)) return 1;
    m_dec = build_decode_matrix(code, pkt, index);
    if (!m_dec) return 1;

    new_pkt = (gf **)xmalloc((size_t)k * sizeof(gf *), "new_pkt_arr");
    for (row = 0; row < k; row++) {
        new_pkt[row] = NULL;
        if (index[row] >= k) {
            new_pkt[row] = (gf *)xmalloc((size_t)sz * sizeof(gf), "new_pkt_row");
            memset(new_pkt[row], 0, (size_t)sz * sizeof(gf));
            for (col = 0; col < k; col++)
                addmul(new_pkt[row], pkt[col], m_dec[row * k + col], sz);
        }
    }
    for (row = 0; row < k; row++) {
        if (new_pkt[row]) {
            memcpy(pkt[row], new_pkt[row], (size_t)sz * sizeof(gf));
            free(new_pkt[row]);
        }
    }
    free(new_pkt);
    free(m_dec);
    return 0;
}
