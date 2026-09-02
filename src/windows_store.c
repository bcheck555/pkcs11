#define SECURITY_WIN32
#include "windows_store.h"
#include "core.h"

#include <bcrypt.h>
#include <ncrypt.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>
#include <winscard.h>

#ifndef CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG
#define CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG 0x00020000
#endif

static void *bridge_alloc(size_t size) {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

static void bridge_free(void *memory) {
    if (memory) HeapFree(GetProcessHeap(), 0, memory);
}

static int provider_is_smartcard(PCCERT_CONTEXT cert) {
    DWORD size = 0;
    CRYPT_KEY_PROV_INFO *info;
    int result = 0;

    if (!CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &size) || !size)
        return 0;
    info = (CRYPT_KEY_PROV_INFO *)bridge_alloc(size);
    if (!info) return 0;
    if (CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, info, &size) && info->pwszProvName) {
        result = _wcsicmp(info->pwszProvName, MS_SMART_CARD_KEY_STORAGE_PROVIDER) == 0 ||
                 _wcsicmp(info->pwszProvName, MS_SCARD_PROV_W) == 0;
    }
    bridge_free(info);
    return result;
}

static int copy_bytes(CK_BYTE **target, CK_ULONG *target_len,
                      const CK_BYTE *source, CK_ULONG source_len) {
    CK_BYTE *copy;
    if (!source || !source_len) return 0;
    copy = (CK_BYTE *)bridge_alloc(source_len);
    if (!copy) return 0;
    memcpy(copy, source, source_len);
    *target = copy;
    *target_len = source_len;
    return 1;
}

static int load_rsa_public_key(BCRYPT_KEY_HANDLE key, bridge_certificate *entry) {
    DWORD size = 0, written = 0;
    BCRYPT_RSAKEY_BLOB *blob;
    CK_BYTE *cursor;
    NTSTATUS status;

    status = BCryptExportKey(key, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &size, 0);
    if (status < 0 || size < sizeof(BCRYPT_RSAKEY_BLOB)) return 0;
    blob = (BCRYPT_RSAKEY_BLOB *)bridge_alloc(size);
    if (!blob) return 0;
    status = BCryptExportKey(key, NULL, BCRYPT_RSAPUBLIC_BLOB, (PUCHAR)blob, size, &written, 0);
    if (status < 0 || written < sizeof(*blob) ||
        blob->Magic != BCRYPT_RSAPUBLIC_MAGIC || !blob->cbModulus || !blob->cbPublicExp) {
        bridge_free(blob);
        return 0;
    }
    cursor = (CK_BYTE *)(blob + 1);
    entry->key_type = CKK_RSA;
    entry->signature_len = blob->cbModulus;
    if (!copy_bytes(&entry->exponent, &entry->exponent_len, cursor, blob->cbPublicExp) ||
        !copy_bytes(&entry->modulus, &entry->modulus_len,
                    cursor + blob->cbPublicExp, blob->cbModulus)) {
        bridge_free(blob);
        return 0;
    }
    bridge_free(blob);
    return 1;
}

static int load_ec_public_key(BCRYPT_KEY_HANDLE key, bridge_certificate *entry) {
    static const CK_BYTE P256_OID[] = {0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07};
    static const CK_BYTE P384_OID[] = {0x06,0x05,0x2b,0x81,0x04,0x00,0x22};
    static const CK_BYTE P521_OID[] = {0x06,0x05,0x2b,0x81,0x04,0x00,0x23};
    DWORD size = 0, written = 0;
    BCRYPT_ECCKEY_BLOB *blob;
    const CK_BYTE *oid = NULL;
    CK_ULONG oid_len = 0;
    size_t ec_point_len = 0;
    NTSTATUS status;

    status = BCryptExportKey(key, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &size, 0);
    if (status < 0 || size < sizeof(BCRYPT_ECCKEY_BLOB)) return 0;
    blob = (BCRYPT_ECCKEY_BLOB *)bridge_alloc(size);
    if (!blob) return 0;
    status = BCryptExportKey(key, NULL, BCRYPT_ECCPUBLIC_BLOB, (PUCHAR)blob, size, &written, 0);
    if (status < 0 || written < sizeof(*blob) + 2 * blob->cbKey) {
        bridge_free(blob);
        return 0;
    }
    switch (blob->dwMagic) {
    case BCRYPT_ECDSA_PUBLIC_P256_MAGIC:
        oid = P256_OID; oid_len = (CK_ULONG)sizeof(P256_OID); break;
    case BCRYPT_ECDSA_PUBLIC_P384_MAGIC:
        oid = P384_OID; oid_len = (CK_ULONG)sizeof(P384_OID); break;
    case BCRYPT_ECDSA_PUBLIC_P521_MAGIC:
        oid = P521_OID; oid_len = (CK_ULONG)sizeof(P521_OID); break;
    default:
        bridge_free(blob); return 0;
    }
    entry->key_type = CKK_EC;
    entry->signature_len = 2 * blob->cbKey;
    if (!bridge_encode_ec_point((CK_BYTE *)(blob + 1), 2 * blob->cbKey,
                                NULL, &ec_point_len)) {
        bridge_free(blob);
        return 0;
    }
    entry->ec_point = (CK_BYTE *)bridge_alloc(ec_point_len);
    if (!entry->ec_point ||
        !bridge_encode_ec_point((CK_BYTE *)(blob + 1), 2 * blob->cbKey,
                                entry->ec_point, &ec_point_len) ||
        !copy_bytes(&entry->ec_params, &entry->ec_params_len, oid, oid_len)) {
        bridge_free(blob);
        return 0;
    }
    entry->ec_point_len = (CK_ULONG)ec_point_len;
    bridge_free(blob);
    return 1;
}

static int load_public_key(PCCERT_CONTEXT cert, bridge_certificate *entry) {
    BCRYPT_KEY_HANDLE key = NULL;
    int result = 0;
    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                    &cert->pCertInfo->SubjectPublicKeyInfo,
                                    0, NULL, &key))
        return 0;
    if (strcmp(cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_RSA_RSA) == 0)
        result = load_rsa_public_key(key, entry);
    else if (strcmp(cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_ECC_PUBLIC_KEY) == 0)
        result = load_ec_public_key(key, entry);
    BCryptDestroyKey(key);
    return result;
}

static void free_entry(bridge_certificate *entry) {
    if (entry->certificate) CertFreeCertificateContext(entry->certificate);
    bridge_free(entry->modulus);
    bridge_free(entry->exponent);
    bridge_free(entry->ec_params);
    bridge_free(entry->ec_point);
    ZeroMemory(entry, sizeof(*entry));
}

CK_RV bridge_store_open(bridge_store *store) {
    PCCERT_CONTEXT current = NULL;
    if (!store) return CKR_ARGUMENTS_BAD;
    ZeroMemory(store, sizeof(*store));
    store->handle = CertOpenSystemStoreW(0, L"MY");
    if (!store->handle) return CKR_DEVICE_ERROR;

    while (store->count < BRIDGE_MAX_CERTIFICATES &&
           (current = CertEnumCertificatesInStore(store->handle, current)) != NULL) {
        bridge_certificate candidate;
        DWORD id_len = sizeof(candidate.id);
        WCHAR wide_label[BRIDGE_MAX_LABEL];
        DWORD wide_label_len;
        int label_len;
        ZeroMemory(&candidate, sizeof(candidate));
        if (!provider_is_smartcard(current)) continue;
        if (!CertGetCertificateContextProperty(current, CERT_HASH_PROP_ID,
                                               candidate.id, &id_len)) continue;
        candidate.id_len = id_len;
        wide_label_len = CertGetNameStringW(current, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                            0, NULL, wide_label,
                                            sizeof(wide_label) / sizeof(wide_label[0]));
        label_len = wide_label_len > 0 ? WideCharToMultiByte(
            CP_UTF8, 0, wide_label, -1, (char *)candidate.label,
            sizeof(candidate.label), NULL, NULL) : 0;
        candidate.label_len = label_len > 0 ? (CK_ULONG)label_len - 1 : 0;
        if (!load_public_key(current, &candidate)) {
            free_entry(&candidate);
            continue;
        }
        candidate.certificate = CertDuplicateCertificateContext(current);
        if (!candidate.certificate) {
            free_entry(&candidate);
            bridge_store_close(store);
            return CKR_HOST_MEMORY;
        }
        store->certificates[store->count++] = candidate;
    }
    return CKR_OK;
}

void bridge_store_close(bridge_store *store) {
    CK_ULONG i;
    if (!store) return;
    for (i = 0; i < store->count; ++i) free_entry(&store->certificates[i]);
    if (store->handle) CertCloseStore(store->handle, 0);
    ZeroMemory(store, sizeof(*store));
}

static LPCWSTR hash_name(bridge_hash_algorithm algorithm) {
    switch (algorithm) {
    case BRIDGE_HASH_SHA1: return BCRYPT_SHA1_ALGORITHM;
    case BRIDGE_HASH_SHA256: return BCRYPT_SHA256_ALGORITHM;
    case BRIDGE_HASH_SHA384: return BCRYPT_SHA384_ALGORITHM;
    case BRIDGE_HASH_SHA512: return BCRYPT_SHA512_ALGORITHM;
    default: return NULL;
    }
}

static ALG_ID capi_hash_id(bridge_hash_algorithm algorithm) {
    switch (algorithm) {
    case BRIDGE_HASH_SHA1: return CALG_SHA1;
    case BRIDGE_HASH_SHA256: return CALG_SHA_256;
    case BRIDGE_HASH_SHA384: return CALG_SHA_384;
    case BRIDGE_HASH_SHA512: return CALG_SHA_512;
    default: return 0;
    }
}

static CK_ULONG hash_length(bridge_hash_algorithm algorithm) {
    switch (algorithm) {
    case BRIDGE_HASH_SHA1: return 20;
    case BRIDGE_HASH_SHA256: return 32;
    case BRIDGE_HASH_SHA384: return 48;
    case BRIDGE_HASH_SHA512: return 64;
    default: return 0;
    }
}

static CK_RV map_windows_error(DWORD error) {
    switch (error) {
    case ERROR_CANCELLED:
    case NTE_USER_CANCELLED:
        return CKR_FUNCTION_CANCELED;
    case SCARD_W_REMOVED_CARD:
    case SCARD_W_CANCELLED_BY_USER:
    case SCARD_E_NO_SMARTCARD:
    case SCARD_E_READER_UNAVAILABLE:
        return CKR_DEVICE_REMOVED;
    case SCARD_W_WRONG_CHV:
        return CKR_PIN_INCORRECT;
    case SCARD_W_CHV_BLOCKED:
        return CKR_PIN_LOCKED;
    case NTE_SILENT_CONTEXT:
        return CKR_USER_NOT_LOGGED_IN;
    case NTE_BAD_KEYSET:
    case NTE_NO_KEY:
        return CKR_KEY_HANDLE_INVALID;
    default:
        return CKR_DEVICE_ERROR;
    }
}

static CK_RV sign_cng(NCRYPT_KEY_HANDLE key, CK_KEY_TYPE key_type,
                      bridge_hash_algorithm algorithm,
                      const CK_BYTE *digest, CK_ULONG digest_len,
                      CK_BYTE *signature, CK_ULONG *signature_len) {
    DWORD result_len = 0;
    SECURITY_STATUS status;
    VOID *padding = NULL;
    DWORD flags = 0;
    BCRYPT_PKCS1_PADDING_INFO padding_info;

    ZeroMemory(&padding_info, sizeof(padding_info));
    if (key_type == CKK_RSA) {
        padding_info.pszAlgId = hash_name(algorithm);
        if (!padding_info.pszAlgId) return CKR_DATA_LEN_RANGE;
        padding = &padding_info;
        flags = NCRYPT_PAD_PKCS1_FLAG;
    }
    status = NCryptSignHash(key, padding, (PBYTE)digest, digest_len,
                           signature, *signature_len, &result_len, flags);
    if (status != ERROR_SUCCESS) return map_windows_error((DWORD)status);
    *signature_len = result_len;
    return CKR_OK;
}

static CK_RV sign_capi(HCRYPTPROV provider, DWORD key_spec,
                       bridge_hash_algorithm algorithm,
                       const CK_BYTE *digest, CK_ULONG digest_len,
                       CK_BYTE *signature, CK_ULONG *signature_len) {
    HCRYPTHASH hash = 0;
    DWORD result_len = *signature_len;
    ALG_ID hash_id = capi_hash_id(algorithm);
    CK_RV result = CKR_DEVICE_ERROR;
    if (!hash_id || digest_len != hash_length(algorithm)) return CKR_DATA_LEN_RANGE;
    if (!CryptCreateHash(provider, hash_id, 0, 0, &hash)) return map_windows_error(GetLastError());
    if (!CryptSetHashParam(hash, HP_HASHVAL, digest, 0)) {
        result = map_windows_error(GetLastError());
        goto done;
    }
    if (!CryptSignHashW(hash, key_spec, NULL, 0, signature, &result_len)) {
        result = map_windows_error(GetLastError());
        goto done;
    }
    bridge_reverse_bytes(signature, result_len);
    *signature_len = result_len;
    result = CKR_OK;
done:
    CryptDestroyHash(hash);
    return result;
}

CK_RV bridge_store_sign(const bridge_certificate *entry,
                        CK_MECHANISM_TYPE mechanism,
                        const CK_BYTE *data, CK_ULONG data_len,
                        CK_BYTE *signature, CK_ULONG *signature_len) {
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
    DWORD key_spec = 0;
    BOOL caller_free = FALSE;
    bridge_hash_algorithm algorithm = BRIDGE_HASH_INVALID;
    const CK_BYTE *digest = data;
    size_t digest_len = data_len;
    CK_RV result;

    if (!entry || !data || !signature || !signature_len) return CKR_ARGUMENTS_BAD;
    if (entry->key_type == CKK_RSA) {
        if (mechanism != CKM_RSA_PKCS ||
            !bridge_parse_digest_info(data, data_len, &algorithm, &digest, &digest_len))
            return CKR_DATA_LEN_RANGE;
    } else if (entry->key_type == CKK_EC) {
        if (mechanism != CKM_ECDSA) return CKR_MECHANISM_INVALID;
    } else {
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    if (!CryptAcquireCertificatePrivateKey(entry->certificate,
            CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG,
            NULL, &key, &key_spec, &caller_free))
        return map_windows_error(GetLastError());

    if (key_spec == CERT_NCRYPT_KEY_SPEC) {
        result = sign_cng((NCRYPT_KEY_HANDLE)key, entry->key_type, algorithm,
                          digest, (CK_ULONG)digest_len, signature, signature_len);
        if (caller_free) NCryptFreeObject((NCRYPT_HANDLE)key);
    } else {
        if (entry->key_type != CKK_RSA) result = CKR_KEY_TYPE_INCONSISTENT;
        else result = sign_capi((HCRYPTPROV)key, key_spec, algorithm,
                                digest, (CK_ULONG)digest_len, signature, signature_len);
        if (caller_free) CryptReleaseContext((HCRYPTPROV)key, 0);
    }
    return result;
}
