#include "core.h"

#include <string.h>

typedef struct digest_prefix {
    bridge_hash_algorithm algorithm;
    const uint8_t *bytes;
    size_t prefix_len;
    size_t digest_len;
} digest_prefix;

static const uint8_t SHA1_PREFIX[] = {
    0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14
};
static const uint8_t SHA256_PREFIX[] = {
    0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
};
static const uint8_t SHA384_PREFIX[] = {
    0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30
};
static const uint8_t SHA512_PREFIX[] = {
    0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40
};

int bridge_parse_digest_info(const uint8_t *data, size_t data_len,
                             bridge_hash_algorithm *algorithm,
                             const uint8_t **digest, size_t *digest_len) {
    static const digest_prefix prefixes[] = {
        { BRIDGE_HASH_SHA1, SHA1_PREFIX, sizeof(SHA1_PREFIX), 20 },
        { BRIDGE_HASH_SHA256, SHA256_PREFIX, sizeof(SHA256_PREFIX), 32 },
        { BRIDGE_HASH_SHA384, SHA384_PREFIX, sizeof(SHA384_PREFIX), 48 },
        { BRIDGE_HASH_SHA512, SHA512_PREFIX, sizeof(SHA512_PREFIX), 64 }
    };
    size_t i;

    if (!data || !algorithm || !digest || !digest_len) return 0;
    for (i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
        const digest_prefix *p = &prefixes[i];
        if (data_len == p->prefix_len + p->digest_len &&
            memcmp(data, p->bytes, p->prefix_len) == 0) {
            *algorithm = p->algorithm;
            *digest = data + p->prefix_len;
            *digest_len = p->digest_len;
            return 1;
        }
    }
    return 0;
}

void bridge_reverse_bytes(uint8_t *data, size_t data_len) {
    size_t i;
    if (!data) return;
    for (i = 0; i < data_len / 2; ++i) {
        uint8_t tmp = data[i];
        data[i] = data[data_len - i - 1];
        data[data_len - i - 1] = tmp;
    }
}

int bridge_encode_ec_point(const uint8_t *xy, size_t xy_len,
                           uint8_t *output, size_t *output_len) {
    size_t value_len = xy_len + 1;
    size_t header_len = value_len > 127 ? 3 : 2;
    size_t required = header_len + value_len;
    if (!xy || !output_len || value_len > 255) return 0;
    if (!output) {
        *output_len = required;
        return 1;
    }
    if (*output_len < required) {
        *output_len = required;
        return 0;
    }
    output[0] = 0x04;
    if (header_len == 2) {
        output[1] = (uint8_t)value_len;
    } else {
        output[1] = 0x81;
        output[2] = (uint8_t)value_len;
    }
    output[header_len] = 0x04;
    memcpy(output + header_len + 1, xy, xy_len);
    *output_len = required;
    return 1;
}
