#ifndef QRH_256_H
#define QRH_256_H

#include <stddef.h>
#include <stdint.h>

void qrh_256(const uint8_t *input, const size_t input_len, uint8_t *out);
uint8_t *qrh_256_hmac(const uint8_t *key, const size_t key_len, const uint8_t *bytes, const size_t bytes_len);

uint8_t *qrh_alloc_256(const uint8_t *input, const size_t input_len);

#endif
