/**
 * qrh_256.c
 *
 * Features:
 *   - QRH-256 hash algorithm implementation
 *   - HMAC variant for keyed hashing
 *   - Stores 32 integers in little-endian format
 */

#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>

#include "qrh_256.h"

#define QRH_HASH_SIZE      32
#define QRH_BLOCK_SIZE     64
#define QRH_WORDS_SIZE     16
#define QRH_CONSTANTS_SIZE 16

#ifndef QRH_HALF_ROUNDS
#define QRH_HALF_ROUNDS   4
#endif

#ifndef QRH_DIFFUSIONS
#define QRH_DIFFUSIONS    4
#endif

#ifndef QRH_MATRIX_ROUNDS 
#define QRH_MATRIX_ROUNDS 2 /* these rounds are very heavy -20 MB/sec per additional round */
#endif

#define ROTL32(v, n) ((v << n) | (v >> (32 - n)))

/* Exported functions */
void qrh_256(const uint8_t *input, const size_t input_len, uint8_t *out);
uint8_t *qrh_256_hmac(const uint8_t *key, const size_t key_len, const uint8_t *bytes, const size_t bytes_len);
uint8_t *qrh_alloc_256(const uint8_t *input, const size_t input_len);

/* Static functions */
static void qrh_run_state(uint32_t state[QRH_WORDS_SIZE]);
static void qrh_finalize(uint32_t words[QRH_WORDS_SIZE], uint8_t out[QRH_HASH_SIZE]);
static void qrh_length_inject(uint32_t words[QRH_WORDS_SIZE], const size_t input_len, const size_t block_index, uint32_t *schema);
static inline void qrh_diffuse_words(uint32_t words[QRH_WORDS_SIZE]);


/* random constants (does not mean safe in active networks) */
static const uint32_t constants[QRH_CONSTANTS_SIZE] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
    0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4
};

uint32_t read_u32_le(const uint8_t *buf, size_t *offset) {
    uint32_t val = buf[*offset] |
                   ((uint32_t)buf[*offset + 1] << 8) |
                   ((uint32_t)buf[*offset + 2] << 16) |
                   ((uint32_t)buf[*offset + 3] << 24);
    *offset += 4;
    return val;
}

void wrno_u32_le(uint8_t *buf, uint32_t val) {
    buf[0] = val & 0xFF;
    buf[1] = val >> 8;
    buf[2] = val >> 16;
    buf[3] = val >> 24;
}

/* crypto functions */
void round4(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *b ^= *d;  *b = ROTL32((*b), 9);  *a = ROTL32((*a), 6);
    *c += *d; *a ^= *c;  *d = ROTL32((*d), 12); *c = ROTL32((*c), 13);
    *a += *b; *c ^= *d;  *b = ROTL32((*d), 14); *a = ROTL32((*a), 25);
    *c += *d; *a ^= *b;  *d = ROTL32((*b), 23);  *c = ROTL32((*c), 30);
}

void round_matrix(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    add3(b, c, a);
    add3(a, c, d);
    round4(a, b, c, d);
    add3(b, d, a);
    add3(b, c, d);
}

void round_matrix3(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    round4(a, b, c, d);

    add3(b, c, a);
    add3(a, c, d);
    
    round4(d, c, b, a);
    
    add3(b, c, a);
    add3(a, c, d);
    
    round4(c, b, a, d);
    
    add3(b, d, a);
    add3(b, c, d);
}

void add3(uint32_t *a, uint32_t *b, uint32_t *c) {
    *a += (*c + *b);
    *b += (*a + *c);
    *c += (*a + *b);

    *a += ROTL32((*c), 19);
    *b += ROTL32((*a), 13);
    *c += ROTL32((*b), 8);
}

void round2(uint32_t *a, uint32_t *b) {
    *a += (*b | *a);
    *b += (*b | *a);

    *a += ROTL32((*a), 13); 
    *b += ROTL32((*b), 14);

    *b ^= ROTL32((*b), 15); 
    *a += ROTL32((*a), 26);

    *a += ROTL32((*a), 11);
    *b += ROTL32((*b), 10);

    *b ^= ROTL32((*a + *b), 23);
    *a ^= ROTL32((*b + *a), 10);
}

/* main functions */
void qrh_256(const uint8_t *input, const size_t input_len, uint8_t *out) {
    size_t offset = 0;

    uint32_t state[QRH_WORDS_SIZE] = {0};
    uint32_t blocks[QRH_WORDS_SIZE] = {0};

    memcpy(state, constants, QRH_WORDS_SIZE * sizeof(uint32_t));
    
    uint32_t schema = constants[(input_len << 8) % QRH_CONSTANTS_SIZE];

    while(offset < input_len) {
        size_t block_size = (input_len - offset) < QRH_BLOCK_SIZE ? (input_len - offset) : QRH_BLOCK_SIZE;

        size_t buffer_offset  = offset;
        size_t full_words     = block_size / 4;
        size_t partial_block  = block_size % 4;

        for(size_t i = 0; i < full_words; i++)
            blocks[i] = read_u32_le(input, &buffer_offset);
        
        if(partial_block)
            blocks[full_words] = (uint32_t)read_u32_le_dynamic(input, &buffer_offset, partial_block);

        for(int i = 0; i < QRH_WORDS_SIZE; i++)
            state[i] ^= blocks[i] + ROTL32(blocks[(i + 1) % 16], i);

        qrh_length_inject(state, input_len, offset, &schema);
        qrh_run_state(state);

        offset = buffer_offset;
    }

    for(int i = 0; i < QRH_WORDS_SIZE; i += 4)
        state[i] ^= ROTL32(input_len << (((i * 5 + 7) % 16) + 10), 6);

    qrh_finalize(state, out);
}

uint8_t *qrh_alloc_256(const uint8_t *input, const size_t input_len) {
    uint8_t *hash = calloc(1, QRH_HASH_SIZE);

    qrh_256(input, input_len, hash);
    return hash;
}

uint8_t *qrh_256_hmac(const uint8_t *key, const size_t key_len, const uint8_t *bytes, const size_t bytes_len) {
    uint8_t key_block[QRH_BLOCK_SIZE]   = {0};
    uint8_t in_padding[QRH_BLOCK_SIZE]  = {0};
    uint8_t out_padding[QRH_BLOCK_SIZE] = {0};

    if(key_len > QRH_BLOCK_SIZE) {
        uint8_t *key_hash = qrh_alloc_256(key, key_len);

        memcpy(key_block, key_hash, QRH_HASH_SIZE);
        free(key_hash);
    } else {
        memcpy(key_block, key, key_len);
    }

    for(int i = 0; i < QRH_BLOCK_SIZE; i++) {
        out_padding[i] = key_block[i] ^ 0x5c;
        in_padding[i]  = key_block[i] ^ 0x36;
    }

    uint8_t *inner_data = calloc(1, QRH_BLOCK_SIZE + bytes_len);
    memcpy(inner_data, in_padding, QRH_BLOCK_SIZE);
    memcpy(inner_data + QRH_BLOCK_SIZE, bytes, bytes_len);

    uint8_t *inner_hash = qrh_alloc_256(inner_data, QRH_BLOCK_SIZE + bytes_len);
    
    uint8_t *outer_data = calloc(1, QRH_BLOCK_SIZE + QRH_HASH_SIZE);
    memcpy(outer_data, out_padding, QRH_BLOCK_SIZE);
    memcpy(outer_data + QRH_BLOCK_SIZE, inner_hash, QRH_HASH_SIZE);

    uint8_t *hmac_hash = qrh_alloc_256(outer_data, QRH_BLOCK_SIZE + QRH_HASH_SIZE);

    free(inner_hash);
    free(inner_data);
    free(outer_data);

    return hmac_hash;
}

static void qrh_length_inject(uint32_t words[QRH_WORDS_SIZE], const size_t input_len, const size_t block_index, uint32_t *schema) {
    uint64_t bit_len = (uint64_t)input_len * 8;

    uint32_t len_lo = (uint32_t)bit_len;
    uint32_t len_hi = (uint32_t)(bit_len >> 32);
    uint32_t blk    = (uint32_t)block_index;

    uint32_t combined = *schema;

    combined ^= ROTL32(blk,    22);
    combined ^= ROTL32(len_lo, 17);
    combined ^= ROTL32(len_hi, 13);

    *schema ^= combined;
    combined += *schema;

    for(int i = 0; i < 4; i++) {
        uint32_t idx_seed = combined ^
                            ROTL32(*schema, 11) ^
                            ROTL32((uint32_t)block_index ^ combined, 23) ^
                            (i * constants[((i + 1) * ROTL32(input_len, 15)) % QRH_CONSTANTS_SIZE]);

        size_t x = idx_seed & (QRH_WORDS_SIZE - 1);
        x = (x + i) & (QRH_WORDS_SIZE - 1); 

        words[x] ^= ROTL32(combined, 9);

        *schema += words[x];
        *schema ^= words[x];

        *schema = ROTL32(*schema, 19);
        combined  ^= *schema;
    }
}

static void qrh_run_state(uint32_t state[QRH_WORDS_SIZE]) {
    for(int i = 0; i < QRH_HALF_ROUNDS; i++) {
        round2(&state[0],  &state[5]);
        round2(&state[1],  &state[6]);
        round2(&state[2],  &state[7]);
        round2(&state[3],  &state[4]);

        round2(&state[4],  &state[9]);
        round2(&state[5],  &state[10]);
        round2(&state[6],  &state[11]);
        round2(&state[7],  &state[8]);

        round2(&state[8],  &state[13]);
        round2(&state[9],  &state[14]);
        round2(&state[10], &state[15]);
        round2(&state[11], &state[12]);

        round2(&state[12], &state[1]);
        round2(&state[13], &state[2]);
        round2(&state[14], &state[3]);
        round2(&state[15], &state[0]);
    }

    for(int i = 0; i < QRH_MATRIX_ROUNDS; i++) {
        /* column quarter-rounds */
        round_matrix(&state[0], &state[4], &state[8], &state[12]);
        round_matrix(&state[1], &state[5], &state[9], &state[13]);
        round_matrix(&state[2], &state[6], &state[10], &state[14]);
        round_matrix(&state[3], &state[7], &state[11], &state[15]);

        /* diagonal quarter-rounds */
        round_matrix(&state[0], &state[5], &state[10], &state[15]);
        round_matrix(&state[1], &state[6], &state[11], &state[12]);
        round_matrix(&state[2], &state[7], &state[8],  &state[13]);
        round_matrix(&state[3], &state[4], &state[9],  &state[14]);
    }

    for(int i = 0; i < QRH_DIFFUSIONS; i++)
        qrh_diffuse_words(state);
}

static inline void qrh_diffuse_words(uint32_t words[QRH_WORDS_SIZE]) {
    for(int i = 0; i < QRH_WORDS_SIZE; i++) {
        words[i] ^= ROTL32(words[(i + 7) % 16], 11);
        words[i] += ROTL32(words[(i + 3) % 16], 17);
    }
}

static void qrh_finalize(uint32_t words[QRH_WORDS_SIZE], uint8_t out[QRH_HASH_SIZE]) {
    for(int i = 0; i < QRH_HASH_SIZE / 4; i++)
        wrno_u32_le(out + (i * 4), words[i]);
}
