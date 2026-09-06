#ifndef PKCS11_BRIDGE_CORE_H
#define PKCS11_BRIDGE_CORE_H

#include <stddef.h>
#include <stdint.h>

typedef enum bridge_hash_algorithm {
    BRIDGE_HASH_INVALID = 0,
    BRIDGE_HASH_SHA1,
    BRIDGE_HASH_SHA256,
    BRIDGE_HASH_SHA384,
    BRIDGE_HASH_SHA512
} bridge_hash_algorithm;

int bridge_rsa_blob_lengths_valid(size_t capacity, size_t written, size_t header_len,
                                  size_t exponent_len, size_t modulus_len);
int bridge_parse_digest_info(const uint8_t *data, size_t data_len,
                             bridge_hash_algorithm *algorithm,
                             const uint8_t **digest, size_t *digest_len);
void bridge_reverse_bytes(uint8_t *data, size_t data_len);
int bridge_encode_ec_point(const uint8_t *xy, size_t xy_len,
                           uint8_t *output, size_t *output_len);

#endif
