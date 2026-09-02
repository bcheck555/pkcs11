#include "core.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
    ++failures; \
} } while (0)

static void test_digest_info(void) {
    static const unsigned char sha1_prefix[] = {
        0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14
    };
    static const unsigned char sha256[] = {
        0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20,
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    };
    static const unsigned char sha384_prefix[] = {
        0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30
    };
    static const unsigned char sha512_prefix[] = {
        0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40
    };
    unsigned char buffer[96] = {0};
    bridge_hash_algorithm algorithm = BRIDGE_HASH_INVALID;
    const unsigned char *digest = NULL;
    size_t digest_len = 0;

    CHECK(bridge_parse_digest_info(sha256, sizeof(sha256), &algorithm, &digest, &digest_len));
    CHECK(algorithm == BRIDGE_HASH_SHA256);
    CHECK(digest_len == 32);
    CHECK(digest && digest[0] == 0 && digest[31] == 31);
    CHECK(!bridge_parse_digest_info(sha256, sizeof(sha256) - 1, &algorithm, &digest, &digest_len));

    memcpy(buffer, sha1_prefix, sizeof(sha1_prefix));
    CHECK(bridge_parse_digest_info(buffer, sizeof(sha1_prefix) + 20,
                                   &algorithm, &digest, &digest_len));
    CHECK(algorithm == BRIDGE_HASH_SHA1 && digest_len == 20);
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, sha384_prefix, sizeof(sha384_prefix));
    CHECK(bridge_parse_digest_info(buffer, sizeof(sha384_prefix) + 48,
                                   &algorithm, &digest, &digest_len));
    CHECK(algorithm == BRIDGE_HASH_SHA384 && digest_len == 48);
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, sha512_prefix, sizeof(sha512_prefix));
    CHECK(bridge_parse_digest_info(buffer, sizeof(sha512_prefix) + 64,
                                   &algorithm, &digest, &digest_len));
    CHECK(algorithm == BRIDGE_HASH_SHA512 && digest_len == 64);
}

static void test_reverse(void) {
    unsigned char odd[] = {1,2,3,4,5};
    unsigned char even[] = {1,2,3,4};
    const unsigned char odd_expected[] = {5,4,3,2,1};
    const unsigned char even_expected[] = {4,3,2,1};
    bridge_reverse_bytes(odd, sizeof(odd));
    bridge_reverse_bytes(even, sizeof(even));
    CHECK(memcmp(odd, odd_expected, sizeof(odd)) == 0);
    CHECK(memcmp(even, even_expected, sizeof(even)) == 0);
}

static void test_ec_point_encoding(void) {
    unsigned char p256[64] = {0};
    unsigned char p521[132] = {0};
    unsigned char encoded[136];
    size_t encoded_len = 0;

    p256[0] = 1; p256[63] = 2;
    CHECK(bridge_encode_ec_point(p256, sizeof(p256), NULL, &encoded_len));
    CHECK(encoded_len == 67);
    CHECK(bridge_encode_ec_point(p256, sizeof(p256), encoded, &encoded_len));
    CHECK(encoded[0] == 0x04 && encoded[1] == 65 && encoded[2] == 0x04);
    CHECK(encoded[3] == 1 && encoded[66] == 2);

    p521[0] = 3; p521[131] = 4; encoded_len = sizeof(encoded);
    CHECK(bridge_encode_ec_point(p521, sizeof(p521), encoded, &encoded_len));
    CHECK(encoded_len == 136);
    CHECK(encoded[0] == 0x04 && encoded[1] == 0x81 && encoded[2] == 133 && encoded[3] == 0x04);
    CHECK(encoded[4] == 3 && encoded[135] == 4);
}

int main(void) {
    test_digest_info();
    test_reverse();
    test_ec_point_encoding();
    if (failures) return 1;
    puts("core tests passed");
    return 0;
}
