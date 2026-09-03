#ifndef PKCS11_BRIDGE_PKCS11_H
#define PKCS11_BRIDGE_PKCS11_H

#ifdef _WIN32
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) __declspec(dllexport) returnType __cdecl name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (__cdecl CK_PTR name)
#else
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (CK_PTR name)
#endif

#if defined(_WIN32)
#pragma pack(push, cryptoki, 1)
#endif

typedef unsigned char CK_BYTE;
typedef CK_BYTE CK_PTR CK_BYTE_PTR;
typedef unsigned char CK_CHAR;
typedef CK_CHAR CK_PTR CK_CHAR_PTR;
typedef unsigned char CK_UTF8CHAR;
typedef CK_UTF8CHAR CK_PTR CK_UTF8CHAR_PTR;
typedef unsigned char CK_BBOOL;
typedef unsigned long CK_ULONG;
typedef CK_ULONG CK_PTR CK_ULONG_PTR;
typedef long CK_LONG;
typedef void CK_PTR CK_VOID_PTR;
typedef CK_VOID_PTR CK_PTR CK_VOID_PTR_PTR;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_SLOT_ID CK_PTR CK_SLOT_ID_PTR;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_SESSION_HANDLE CK_PTR CK_SESSION_HANDLE_PTR;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_OBJECT_HANDLE CK_PTR CK_OBJECT_HANDLE_PTR;
typedef CK_ULONG CK_FLAGS;
typedef CK_ULONG CK_USER_TYPE;
typedef CK_ULONG CK_STATE;
typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_ULONG CK_KEY_TYPE;
typedef CK_ULONG CK_CERTIFICATE_TYPE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_MECHANISM_TYPE CK_PTR CK_MECHANISM_TYPE_PTR;
typedef CK_ULONG CK_NOTIFICATION;

#define CK_TRUE 1
#define CK_FALSE 0
#define CK_UNAVAILABLE_INFORMATION (~0UL)
#define CK_INVALID_HANDLE 0UL

typedef struct CK_VERSION { CK_BYTE major; CK_BYTE minor; } CK_VERSION;
typedef struct CK_INFO {
    CK_VERSION cryptokiVersion;
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_UTF8CHAR libraryDescription[32];
    CK_VERSION libraryVersion;
} CK_INFO;
typedef CK_INFO CK_PTR CK_INFO_PTR;

typedef struct CK_SLOT_INFO {
    CK_UTF8CHAR slotDescription[64];
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
} CK_SLOT_INFO;
typedef CK_SLOT_INFO CK_PTR CK_SLOT_INFO_PTR;

typedef struct CK_TOKEN_INFO {
    CK_UTF8CHAR label[32];
    CK_UTF8CHAR manufacturerID[32];
    CK_UTF8CHAR model[16];
    CK_CHAR serialNumber[16];
    CK_FLAGS flags;
    CK_ULONG ulMaxSessionCount;
    CK_ULONG ulSessionCount;
    CK_ULONG ulMaxRwSessionCount;
    CK_ULONG ulRwSessionCount;
    CK_ULONG ulMaxPinLen;
    CK_ULONG ulMinPinLen;
    CK_ULONG ulTotalPublicMemory;
    CK_ULONG ulFreePublicMemory;
    CK_ULONG ulTotalPrivateMemory;
    CK_ULONG ulFreePrivateMemory;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
    CK_CHAR utcTime[16];
} CK_TOKEN_INFO;
typedef CK_TOKEN_INFO CK_PTR CK_TOKEN_INFO_PTR;

typedef struct CK_SESSION_INFO {
    CK_SLOT_ID slotID;
    CK_STATE state;
    CK_FLAGS flags;
    CK_ULONG ulDeviceError;
} CK_SESSION_INFO;
typedef CK_SESSION_INFO CK_PTR CK_SESSION_INFO_PTR;

typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
} CK_ATTRIBUTE;
typedef CK_ATTRIBUTE CK_PTR CK_ATTRIBUTE_PTR;

typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;
typedef CK_MECHANISM CK_PTR CK_MECHANISM_PTR;

typedef struct CK_MECHANISM_INFO {
    CK_ULONG ulMinKeySize;
    CK_ULONG ulMaxKeySize;
    CK_FLAGS flags;
} CK_MECHANISM_INFO;
typedef CK_MECHANISM_INFO CK_PTR CK_MECHANISM_INFO_PTR;

typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST CK_PTR CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR CK_PTR CK_FUNCTION_LIST_PTR_PTR;

struct CK_FUNCTION_LIST {
    CK_VERSION version;
    CK_VOID_PTR C_Initialize;
    CK_VOID_PTR C_Finalize;
    CK_VOID_PTR C_GetInfo;
    CK_VOID_PTR C_GetFunctionList;
    CK_VOID_PTR C_GetSlotList;
    CK_VOID_PTR C_GetSlotInfo;
    CK_VOID_PTR C_GetTokenInfo;
    CK_VOID_PTR C_GetMechanismList;
    CK_VOID_PTR C_GetMechanismInfo;
    CK_VOID_PTR C_InitToken;
    CK_VOID_PTR C_InitPIN;
    CK_VOID_PTR C_SetPIN;
    CK_VOID_PTR C_OpenSession;
    CK_VOID_PTR C_CloseSession;
    CK_VOID_PTR C_CloseAllSessions;
    CK_VOID_PTR C_GetSessionInfo;
    CK_VOID_PTR C_GetOperationState;
    CK_VOID_PTR C_SetOperationState;
    CK_VOID_PTR C_Login;
    CK_VOID_PTR C_Logout;
    CK_VOID_PTR C_CreateObject;
    CK_VOID_PTR C_CopyObject;
    CK_VOID_PTR C_DestroyObject;
    CK_VOID_PTR C_GetObjectSize;
    CK_VOID_PTR C_GetAttributeValue;
    CK_VOID_PTR C_SetAttributeValue;
    CK_VOID_PTR C_FindObjectsInit;
    CK_VOID_PTR C_FindObjects;
    CK_VOID_PTR C_FindObjectsFinal;
    CK_VOID_PTR C_EncryptInit;
    CK_VOID_PTR C_Encrypt;
    CK_VOID_PTR C_EncryptUpdate;
    CK_VOID_PTR C_EncryptFinal;
    CK_VOID_PTR C_DecryptInit;
    CK_VOID_PTR C_Decrypt;
    CK_VOID_PTR C_DecryptUpdate;
    CK_VOID_PTR C_DecryptFinal;
    CK_VOID_PTR C_DigestInit;
    CK_VOID_PTR C_Digest;
    CK_VOID_PTR C_DigestUpdate;
    CK_VOID_PTR C_DigestKey;
    CK_VOID_PTR C_DigestFinal;
    CK_VOID_PTR C_SignInit;
    CK_VOID_PTR C_Sign;
    CK_VOID_PTR C_SignUpdate;
    CK_VOID_PTR C_SignFinal;
    CK_VOID_PTR C_SignRecoverInit;
    CK_VOID_PTR C_SignRecover;
    CK_VOID_PTR C_VerifyInit;
    CK_VOID_PTR C_Verify;
    CK_VOID_PTR C_VerifyUpdate;
    CK_VOID_PTR C_VerifyFinal;
    CK_VOID_PTR C_VerifyRecoverInit;
    CK_VOID_PTR C_VerifyRecover;
    CK_VOID_PTR C_DigestEncryptUpdate;
    CK_VOID_PTR C_DecryptDigestUpdate;
    CK_VOID_PTR C_SignEncryptUpdate;
    CK_VOID_PTR C_DecryptVerifyUpdate;
    CK_VOID_PTR C_GenerateKey;
    CK_VOID_PTR C_GenerateKeyPair;
    CK_VOID_PTR C_WrapKey;
    CK_VOID_PTR C_UnwrapKey;
    CK_VOID_PTR C_DeriveKey;
    CK_VOID_PTR C_SeedRandom;
    CK_VOID_PTR C_GenerateRandom;
    CK_VOID_PTR C_GetFunctionStatus;
    CK_VOID_PTR C_CancelFunction;
    CK_VOID_PTR C_WaitForSlotEvent;
};

/* Return values. */
#define CKR_OK 0x00000000UL
#define CKR_CANCEL 0x00000001UL
#define CKR_HOST_MEMORY 0x00000002UL
#define CKR_SLOT_ID_INVALID 0x00000003UL
#define CKR_GENERAL_ERROR 0x00000005UL
#define CKR_FUNCTION_FAILED 0x00000006UL
#define CKR_ARGUMENTS_BAD 0x00000007UL
#define CKR_ATTRIBUTE_TYPE_INVALID 0x00000012UL
#define CKR_ATTRIBUTE_VALUE_INVALID 0x00000013UL
#define CKR_DATA_LEN_RANGE 0x00000021UL
#define CKR_DEVICE_ERROR 0x00000030UL
#define CKR_DEVICE_REMOVED 0x00000032UL
#define CKR_FUNCTION_CANCELED 0x00000050UL
#define CKR_FUNCTION_NOT_SUPPORTED 0x00000054UL
#define CKR_KEY_HANDLE_INVALID 0x00000060UL
#define CKR_KEY_TYPE_INCONSISTENT 0x00000063UL
#define CKR_MECHANISM_INVALID 0x00000070UL
#define CKR_OBJECT_HANDLE_INVALID 0x00000082UL
#define CKR_OPERATION_ACTIVE 0x00000090UL
#define CKR_OPERATION_NOT_INITIALIZED 0x00000091UL
#define CKR_PIN_INCORRECT 0x000000A0UL
#define CKR_PIN_LOCKED 0x000000A4UL
#define CKR_SESSION_CLOSED 0x000000B0UL
#define CKR_SESSION_COUNT 0x000000B1UL
#define CKR_SESSION_HANDLE_INVALID 0x000000B3UL
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED 0x000000B4UL
#define CKR_SESSION_READ_ONLY 0x000000B5UL
#define CKR_SIGNATURE_LEN_RANGE 0x000000C1UL
#define CKR_TEMPLATE_INCOMPLETE 0x000000D0UL
#define CKR_TEMPLATE_INCONSISTENT 0x000000D1UL
#define CKR_TOKEN_NOT_PRESENT 0x000000E0UL
#define CKR_USER_ALREADY_LOGGED_IN 0x00000100UL
#define CKR_USER_NOT_LOGGED_IN 0x00000101UL
#define CKR_BUFFER_TOO_SMALL 0x00000150UL
#define CKR_CRYPTOKI_NOT_INITIALIZED 0x00000190UL
#define CKR_CRYPTOKI_ALREADY_INITIALIZED 0x00000191UL

/* Flags, states, classes, types, attributes, and mechanisms. */
#define CKF_TOKEN_PRESENT 0x00000001UL
#define CKF_REMOVABLE_DEVICE 0x00000002UL
#define CKF_HW_SLOT 0x00000004UL
#define CKF_RNG 0x00000001UL
#define CKF_WRITE_PROTECTED 0x00000002UL
#define CKF_TOKEN_INITIALIZED 0x00000400UL
#define CKF_SERIAL_SESSION 0x00000004UL
#define CKF_RW_SESSION 0x00000002UL
#define CKF_SIGN 0x00000800UL
#define CKS_RO_PUBLIC_SESSION 0UL
#define CKS_RW_PUBLIC_SESSION 2UL
#define CKU_USER 1UL
#define CKO_CERTIFICATE 0x00000001UL
#define CKO_PUBLIC_KEY 0x00000002UL
#define CKO_PRIVATE_KEY 0x00000003UL
#define CKC_X_509 0x00000000UL
#define CKK_RSA 0x00000000UL
#define CKK_EC 0x00000003UL
#define CKA_CLASS 0x00000000UL
#define CKA_TOKEN 0x00000001UL
#define CKA_PRIVATE 0x00000002UL
#define CKA_LABEL 0x00000003UL
#define CKA_VALUE 0x00000011UL
#define CKA_CERTIFICATE_TYPE 0x00000080UL
#define CKA_SUBJECT 0x00000081UL
#define CKA_KEY_TYPE 0x00000100UL
#define CKA_ID 0x00000102UL
#define CKA_SENSITIVE 0x00000103UL
#define CKA_MODULUS 0x00000120UL
#define CKA_MODULUS_BITS 0x00000121UL
#define CKA_PUBLIC_EXPONENT 0x00000122UL
#define CKA_SIGN 0x00000108UL
#define CKA_VERIFY 0x0000010AUL
#define CKA_EC_PARAMS 0x00000180UL
#define CKA_EC_POINT 0x00000181UL
#define CKA_ALWAYS_AUTHENTICATE 0x00000202UL
#define CKM_RSA_PKCS 0x00000001UL
#define CKM_ECDSA 0x00001041UL

#if defined(_WIN32)
#pragma pack(pop, cryptoki)
#endif

#endif
