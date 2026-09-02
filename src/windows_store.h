#ifndef PKCS11_BRIDGE_WINDOWS_STORE_H
#define PKCS11_BRIDGE_WINDOWS_STORE_H

#include <windows.h>
#include <wincrypt.h>

#include "pkcs11.h"

#define BRIDGE_MAX_CERTIFICATES 32
#define BRIDGE_MAX_LABEL 128

typedef struct bridge_certificate {
    PCCERT_CONTEXT certificate;
    CK_BYTE id[20];
    CK_ULONG id_len;
    CK_CHAR label[BRIDGE_MAX_LABEL];
    CK_ULONG label_len;
    CK_KEY_TYPE key_type;
    CK_BYTE *modulus;
    CK_ULONG modulus_len;
    CK_BYTE *exponent;
    CK_ULONG exponent_len;
    CK_BYTE *ec_params;
    CK_ULONG ec_params_len;
    CK_BYTE *ec_point;
    CK_ULONG ec_point_len;
    CK_ULONG signature_len;
} bridge_certificate;

typedef struct bridge_store {
    HCERTSTORE handle;
    bridge_certificate certificates[BRIDGE_MAX_CERTIFICATES];
    CK_ULONG count;
} bridge_store;

CK_RV bridge_store_open(bridge_store *store);
void bridge_store_close(bridge_store *store);
CK_RV bridge_store_sign(const bridge_certificate *entry,
                        CK_MECHANISM_TYPE mechanism,
                        const CK_BYTE *data, CK_ULONG data_len,
                        CK_BYTE *signature, CK_ULONG *signature_len);

#endif
