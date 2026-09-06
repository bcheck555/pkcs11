#if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0600
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include "pkcs11.h"
#include "windows_store.h"

#include <windows.h>
#include <string.h>

#define BRIDGE_SLOT_ID 1UL
#define BRIDGE_MAX_SESSIONS 64
#define BRIDGE_OBJECTS_PER_CERT 3
#define BRIDGE_MAX_FIND_RESULTS (BRIDGE_MAX_CERTIFICATES * BRIDGE_OBJECTS_PER_CERT)
#define OBJECT_CERTIFICATE 1UL
#define OBJECT_PUBLIC_KEY 2UL
#define OBJECT_PRIVATE_KEY 3UL

typedef struct bridge_session {
    int active;
    CK_SESSION_HANDLE handle;
    CK_FLAGS flags;
    int find_active;
    CK_OBJECT_HANDLE matches[BRIDGE_MAX_FIND_RESULTS];
    CK_ULONG match_count;
    CK_ULONG match_index;
    int sign_active;
    CK_ULONG sign_certificate_index;
    CK_MECHANISM_TYPE sign_mechanism;
} bridge_session;

static SRWLOCK state_lock = SRWLOCK_INIT;
static int initialized;
static CK_SESSION_HANDLE next_session_handle = 1;
static bridge_store certificate_store;
static bridge_session sessions[BRIDGE_MAX_SESSIONS];

static CK_RV unsupported(void) { return CKR_FUNCTION_NOT_SUPPORTED; }

static void fill_padded(CK_UTF8CHAR *target, size_t target_len, const char *source) {
    size_t i = 0;
    memset(target, ' ', target_len);
    if (!source) return;
    while (i < target_len && source[i]) {
        target[i] = (CK_UTF8CHAR)source[i];
        ++i;
    }
}

static bridge_session *find_session(CK_SESSION_HANDLE handle) {
    CK_ULONG i;
    for (i = 0; i < BRIDGE_MAX_SESSIONS; ++i)
        if (sessions[i].active && sessions[i].handle == handle) return &sessions[i];
    return NULL;
}

static CK_OBJECT_HANDLE object_handle(CK_ULONG certificate_index, CK_ULONG kind) {
    return (certificate_index + 1) * 10 + kind;
}

static int decode_object(CK_OBJECT_HANDLE object, CK_ULONG *certificate_index, CK_ULONG *kind) {
    CK_ULONG group = object / 10;
    CK_ULONG object_kind = object % 10;
    if (!group || group > certificate_store.count ||
        object_kind < OBJECT_CERTIFICATE || object_kind > OBJECT_PRIVATE_KEY)
        return 0;
    *certificate_index = group - 1;
    *kind = object_kind;
    return 1;
}

static CK_OBJECT_CLASS class_for_kind(CK_ULONG kind) {
    if (kind == OBJECT_CERTIFICATE) return CKO_CERTIFICATE;
    if (kind == OBJECT_PUBLIC_KEY) return CKO_PUBLIC_KEY;
    return CKO_PRIVATE_KEY;
}

static int object_matches(const bridge_certificate *entry, CK_ULONG kind,
                          CK_ATTRIBUTE_PTR attributes, CK_ULONG count) {
    CK_ULONG i;
    for (i = 0; i < count; ++i) {
        CK_ATTRIBUTE *a = &attributes[i];
        if (!a->pValue) return 0;
        switch (a->type) {
        case CKA_CLASS:
            if (a->ulValueLen != sizeof(CK_OBJECT_CLASS) ||
                *(CK_OBJECT_CLASS *)a->pValue != class_for_kind(kind)) return 0;
            break;
        case CKA_ID:
            if (a->ulValueLen != entry->id_len ||
                memcmp(a->pValue, entry->id, entry->id_len) != 0) return 0;
            break;
        case CKA_KEY_TYPE:
            if (kind == OBJECT_CERTIFICATE || a->ulValueLen != sizeof(CK_KEY_TYPE) ||
                *(CK_KEY_TYPE *)a->pValue != entry->key_type) return 0;
            break;
        case CKA_TOKEN:
            if (a->ulValueLen != sizeof(CK_BBOOL) || *(CK_BBOOL *)a->pValue != CK_TRUE)
                return 0;
            break;
        case CKA_SIGN:
            if (a->ulValueLen != sizeof(CK_BBOOL) ||
                *(CK_BBOOL *)a->pValue != (kind == OBJECT_PRIVATE_KEY ? CK_TRUE : CK_FALSE))
                return 0;
            break;
        case CKA_LABEL:
            if (a->ulValueLen != entry->label_len ||
                memcmp(a->pValue, entry->label, entry->label_len) != 0) return 0;
            break;
        default:
            return 0;
        }
    }
    return 1;
}

static CK_RV copy_attribute(CK_ATTRIBUTE *attribute, const void *value, CK_ULONG value_len) {
    if (!attribute->pValue) {
        attribute->ulValueLen = value_len;
        return CKR_OK;
    }
    if (attribute->ulValueLen < value_len) {
        attribute->ulValueLen = value_len;
        return CKR_BUFFER_TOO_SMALL;
    }
    if (value_len) memcpy(attribute->pValue, value, value_len);
    attribute->ulValueLen = value_len;
    return CKR_OK;
}

static CK_RV get_one_attribute(const bridge_certificate *entry, CK_ULONG kind,
                               CK_ATTRIBUTE *attribute) {
    CK_OBJECT_CLASS object_class = class_for_kind(kind);
    CK_BBOOL true_value = CK_TRUE, false_value = CK_FALSE;
    CK_CERTIFICATE_TYPE certificate_type = CKC_X_509;
    CK_ULONG modulus_bits = entry->modulus_len * 8;

    switch (attribute->type) {
    case CKA_CLASS:
        return copy_attribute(attribute, &object_class, sizeof(object_class));
    case CKA_TOKEN:
        return copy_attribute(attribute, &true_value, sizeof(true_value));
    case CKA_LABEL:
        return copy_attribute(attribute, entry->label, entry->label_len);
    case CKA_ID:
        return copy_attribute(attribute, entry->id, entry->id_len);
    case CKA_PRIVATE:
        return copy_attribute(attribute,
            kind == OBJECT_PRIVATE_KEY ? &true_value : &false_value, sizeof(CK_BBOOL));
    case CKA_CERTIFICATE_TYPE:
        if (kind != OBJECT_CERTIFICATE) break;
        return copy_attribute(attribute, &certificate_type, sizeof(certificate_type));
    case CKA_VALUE:
        if (kind != OBJECT_CERTIFICATE) break;
        return copy_attribute(attribute, entry->certificate->pbCertEncoded,
                              entry->certificate->cbCertEncoded);
    case CKA_SUBJECT:
        if (kind != OBJECT_CERTIFICATE) break;
        return copy_attribute(attribute, entry->certificate->pCertInfo->Subject.pbData,
                              entry->certificate->pCertInfo->Subject.cbData);
    case CKA_KEY_TYPE:
        if (kind == OBJECT_CERTIFICATE) break;
        return copy_attribute(attribute, &entry->key_type, sizeof(entry->key_type));
    case CKA_SIGN:
        if (kind == OBJECT_CERTIFICATE) break;
        return copy_attribute(attribute,
            kind == OBJECT_PRIVATE_KEY ? &true_value : &false_value, sizeof(CK_BBOOL));
    case CKA_VERIFY:
        if (kind == OBJECT_CERTIFICATE) break;
        return copy_attribute(attribute,
            kind == OBJECT_PUBLIC_KEY ? &true_value : &false_value, sizeof(CK_BBOOL));
    case CKA_SENSITIVE:
        if (kind != OBJECT_PRIVATE_KEY) break;
        return copy_attribute(attribute, &true_value, sizeof(true_value));
    case CKA_ALWAYS_AUTHENTICATE:
        if (kind != OBJECT_PRIVATE_KEY) break;
        return copy_attribute(attribute, &false_value, sizeof(false_value));
    case CKA_MODULUS:
        if (kind == OBJECT_CERTIFICATE || entry->key_type != CKK_RSA) break;
        return copy_attribute(attribute, entry->modulus, entry->modulus_len);
    case CKA_PUBLIC_EXPONENT:
        if (kind == OBJECT_CERTIFICATE || entry->key_type != CKK_RSA) break;
        return copy_attribute(attribute, entry->exponent, entry->exponent_len);
    case CKA_MODULUS_BITS:
        if (kind == OBJECT_CERTIFICATE || entry->key_type != CKK_RSA) break;
        return copy_attribute(attribute, &modulus_bits, sizeof(modulus_bits));
    case CKA_EC_PARAMS:
        if (kind == OBJECT_CERTIFICATE || entry->key_type != CKK_EC) break;
        return copy_attribute(attribute, entry->ec_params, entry->ec_params_len);
    case CKA_EC_POINT:
        if (kind == OBJECT_CERTIFICATE || entry->key_type != CKK_EC) break;
        return copy_attribute(attribute, entry->ec_point, entry->ec_point_len);
    default:
        break;
    }
    attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION;
    return CKR_ATTRIBUTE_TYPE_INVALID;
}

static CK_RV bridge_C_Initialize(CK_VOID_PTR arguments) {
    CK_RV result;
    (void)arguments;
    AcquireSRWLockExclusive(&state_lock);
    if (initialized) {
        ReleaseSRWLockExclusive(&state_lock);
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    ZeroMemory(sessions, sizeof(sessions));
    result = bridge_store_open(&certificate_store);
    if (result == CKR_OK) initialized = 1;
    ReleaseSRWLockExclusive(&state_lock);
    return result;
}

static CK_RV bridge_C_Finalize(CK_VOID_PTR reserved) {
    if (reserved) return CKR_ARGUMENTS_BAD;
    AcquireSRWLockExclusive(&state_lock);
    if (!initialized) {
        ReleaseSRWLockExclusive(&state_lock);
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    bridge_store_close(&certificate_store);
    ZeroMemory(sessions, sizeof(sessions));
    initialized = 0;
    ReleaseSRWLockExclusive(&state_lock);
    return CKR_OK;
}

static CK_RV bridge_C_GetInfo(CK_INFO_PTR info) {
    if (!info) return CKR_ARGUMENTS_BAD;
    AcquireSRWLockShared(&state_lock);
    if (!initialized) {
        ReleaseSRWLockShared(&state_lock);
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    ZeroMemory(info, sizeof(*info));
    info->cryptokiVersion.major = 2; info->cryptokiVersion.minor = 40;
    fill_padded(info->manufacturerID, sizeof(info->manufacturerID), "Native Windows");
    fill_padded(info->libraryDescription, sizeof(info->libraryDescription), "CNG/CAPI Smart Card Bridge");
    info->libraryVersion.major = 0; info->libraryVersion.minor = 1;
    ReleaseSRWLockShared(&state_lock);
    return CKR_OK;
}

static CK_RV bridge_C_GetSlotList(CK_BBOOL token_present, CK_SLOT_ID_PTR slots,
                                  CK_ULONG_PTR count) {
    CK_ULONG available;
    if (!count) return CKR_ARGUMENTS_BAD;
    AcquireSRWLockShared(&state_lock);
    if (!initialized) {
        ReleaseSRWLockShared(&state_lock);
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    available = (!token_present || certificate_store.count > 0) ? 1 : 0;
    if (!slots) {
        *count = available;
    } else if (*count < available) {
        *count = available;
        ReleaseSRWLockShared(&state_lock);
        return CKR_BUFFER_TOO_SMALL;
    } else {
        if (available) slots[0] = BRIDGE_SLOT_ID;
        *count = available;
    }
    ReleaseSRWLockShared(&state_lock);
    return CKR_OK;
}

static CK_RV bridge_C_GetSlotInfo(CK_SLOT_ID slot, CK_SLOT_INFO_PTR info) {
    if (slot != BRIDGE_SLOT_ID) return CKR_SLOT_ID_INVALID;
    if (!info) return CKR_ARGUMENTS_BAD;
    ZeroMemory(info, sizeof(*info));
    fill_padded(info->slotDescription, sizeof(info->slotDescription), "Windows CurrentUser smart cards");
    fill_padded(info->manufacturerID, sizeof(info->manufacturerID), "Native Windows");
    info->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
    if (certificate_store.count) info->flags |= CKF_TOKEN_PRESENT;
    info->hardwareVersion.major = 1;
    info->firmwareVersion.major = 1;
    return CKR_OK;
}

static CK_RV bridge_C_GetTokenInfo(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info) {
    if (slot != BRIDGE_SLOT_ID) return CKR_SLOT_ID_INVALID;
    if (!info) return CKR_ARGUMENTS_BAD;
    if (!certificate_store.count) return CKR_TOKEN_NOT_PRESENT;
    ZeroMemory(info, sizeof(*info));
    fill_padded(info->label, sizeof(info->label), "Windows Smart Card");
    fill_padded(info->manufacturerID, sizeof(info->manufacturerID), "Native Windows");
    fill_padded(info->model, sizeof(info->model), "CNG/CAPI");
    fill_padded((CK_UTF8CHAR *)info->serialNumber, sizeof(info->serialNumber), "CERTSTORE");
    info->flags = CKF_TOKEN_INITIALIZED | CKF_WRITE_PROTECTED;
    info->ulMaxSessionCount = BRIDGE_MAX_SESSIONS;
    info->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
    info->ulMaxRwSessionCount = BRIDGE_MAX_SESSIONS;
    info->ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
    info->ulMaxPinLen = 0;
    info->ulMinPinLen = 0;
    info->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    info->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
    info->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    info->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    info->hardwareVersion.major = 1;
    info->firmwareVersion.major = 1;
    memset(info->utcTime, ' ', sizeof(info->utcTime));
    return CKR_OK;
}

static CK_RV bridge_C_GetMechanismList(CK_SLOT_ID slot, CK_MECHANISM_TYPE_PTR mechanisms,
                                       CK_ULONG_PTR count) {
    const CK_MECHANISM_TYPE supported[] = { CKM_RSA_PKCS, CKM_ECDSA };
    if (slot != BRIDGE_SLOT_ID) return CKR_SLOT_ID_INVALID;
    if (!count) return CKR_ARGUMENTS_BAD;
    if (!mechanisms) {
        *count = 2;
        return CKR_OK;
    }
    if (*count < 2) {
        *count = 2;
        return CKR_BUFFER_TOO_SMALL;
    }
    memcpy(mechanisms, supported, sizeof(supported));
    *count = 2;
    return CKR_OK;
}

static CK_RV bridge_C_GetMechanismInfo(CK_SLOT_ID slot, CK_MECHANISM_TYPE mechanism,
                                       CK_MECHANISM_INFO_PTR info) {
    if (slot != BRIDGE_SLOT_ID) return CKR_SLOT_ID_INVALID;
    if (!info) return CKR_ARGUMENTS_BAD;
    ZeroMemory(info, sizeof(*info));
    info->flags = CKF_SIGN;
    if (mechanism == CKM_RSA_PKCS) {
        info->ulMinKeySize = 1024; info->ulMaxKeySize = 16384;
    } else if (mechanism == CKM_ECDSA) {
        info->ulMinKeySize = 256; info->ulMaxKeySize = 521;
    } else return CKR_MECHANISM_INVALID;
    return CKR_OK;
}

static CK_RV bridge_C_OpenSession(CK_SLOT_ID slot, CK_FLAGS flags,
                                  CK_VOID_PTR application, CK_VOID_PTR notify,
                                  CK_SESSION_HANDLE_PTR session_handle) {
    CK_ULONG i;
    (void)application; (void)notify;
    if (slot != BRIDGE_SLOT_ID) return CKR_SLOT_ID_INVALID;
    if (!session_handle) return CKR_ARGUMENTS_BAD;
    if (!(flags & CKF_SERIAL_SESSION)) return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    AcquireSRWLockExclusive(&state_lock);
    if (!initialized) {
        ReleaseSRWLockExclusive(&state_lock);
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (!certificate_store.count) {
        ReleaseSRWLockExclusive(&state_lock);
        return CKR_TOKEN_NOT_PRESENT;
    }
    for (i = 0; i < BRIDGE_MAX_SESSIONS; ++i) if (!sessions[i].active) {
        ZeroMemory(&sessions[i], sizeof(sessions[i]));
        sessions[i].active = 1;
        sessions[i].flags = flags;
        sessions[i].handle = next_session_handle++;
        if (!sessions[i].handle) sessions[i].handle = next_session_handle++;
        *session_handle = sessions[i].handle;
        ReleaseSRWLockExclusive(&state_lock);
        return CKR_OK;
    }
    ReleaseSRWLockExclusive(&state_lock);
    return CKR_SESSION_COUNT;
}

static CK_RV bridge_C_CloseSession(CK_SESSION_HANDLE handle) {
    bridge_session *session;
    AcquireSRWLockExclusive(&state_lock);
    session = find_session(handle);
    if (!session) {
        ReleaseSRWLockExclusive(&state_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }
    ZeroMemory(session, sizeof(*session));
    ReleaseSRWLockExclusive(&state_lock);
    return CKR_OK;
}

static CK_RV bridge_C_CloseAllSessions(CK_SLOT_ID slot) {
    if (slot != BRIDGE_SLOT_ID) return CKR_SLOT_ID_INVALID;
    AcquireSRWLockExclusive(&state_lock);
    ZeroMemory(sessions, sizeof(sessions));
    ReleaseSRWLockExclusive(&state_lock);
    return CKR_OK;
}

static CK_RV bridge_C_GetSessionInfo(CK_SESSION_HANDLE handle, CK_SESSION_INFO_PTR info) {
    bridge_session *session;
    if (!info) return CKR_ARGUMENTS_BAD;
    AcquireSRWLockShared(&state_lock);
    session = find_session(handle);
    if (!session) {
        ReleaseSRWLockShared(&state_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }
    info->slotID = BRIDGE_SLOT_ID;
    info->state = (session->flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
    info->flags = session->flags;
    info->ulDeviceError = 0;
    ReleaseSRWLockShared(&state_lock);
    return CKR_OK;
}

static CK_RV bridge_C_Login(CK_SESSION_HANDLE handle, CK_USER_TYPE user_type,
                            CK_UTF8CHAR_PTR pin, CK_ULONG pin_len) {
    (void)handle; (void)user_type; (void)pin; (void)pin_len;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV bridge_C_Logout(CK_SESSION_HANDLE handle) {
    (void)handle;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV bridge_C_FindObjectsInit(CK_SESSION_HANDLE handle,
                                      CK_ATTRIBUTE_PTR attributes, CK_ULONG count) {
    bridge_session *session;
    CK_ULONG i, kind;
    if (count && !attributes) return CKR_ARGUMENTS_BAD;
    AcquireSRWLockExclusive(&state_lock);
    session = find_session(handle);
    if (!session) {
        ReleaseSRWLockExclusive(&state_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (session->find_active) {
        ReleaseSRWLockExclusive(&state_lock);
        return CKR_OPERATION_ACTIVE;
    }
    session->match_count = session->match_index = 0;
    for (i = 0; i < certificate_store.count; ++i) {
        for (kind = OBJECT_CERTIFICATE; kind <= OBJECT_PRIVATE_KEY; ++kind) {
            if (object_matches(&certificate_store.certificates[i], kind, attributes, count))
                session->matches[session->match_count++] = object_handle(i, kind);
        }
    }
    session->find_active = 1;
    ReleaseSRWLockExclusive(&state_lock);
    return CKR_OK;
}

static CK_RV bridge_C_FindObjects(CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE_PTR objects,
                                  CK_ULONG max_count, CK_ULONG_PTR object_count) {
    bridge_session *session;
    CK_ULONG copied = 0;
    if (!objects || !object_count) return CKR_ARGUMENTS_BAD;
    AcquireSRWLockExclusive(&state_lock);
    session = find_session(handle);
    if (!session) {
        ReleaseSRWLockExclusive(&state_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!session->find_active) {
        ReleaseSRWLockExclusive(&state_lock);
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    while (copied < max_count && session->match_index < session->match_count)
        objects[copied++] = session->matches[session->match_index++];
    *object_count = copied;
    ReleaseSRWLockExclusive(&state_lock);
    return CKR_OK;
}

static CK_RV bridge_C_FindObjectsFinal(CK_SESSION_HANDLE handle) {
    bridge_session *session;
    AcquireSRWLockExclusive(&state_lock);
    session = find_session(handle);
    if (!session) {
        ReleaseSRWLockExclusive(&state_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!session->find_active) {
        ReleaseSRWLockExclusive(&state_lock);
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    session->find_active = 0;
    session->match_count = session->match_index = 0;
    ReleaseSRWLockExclusive(&state_lock);
    return CKR_OK;
}

static CK_RV bridge_C_GetAttributeValue(CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object,
                                        CK_ATTRIBUTE_PTR attributes, CK_ULONG count) {
    CK_ULONG certificate_index, kind, i;
    CK_RV result = CKR_OK;
    if (count && !attributes) return CKR_ARGUMENTS_BAD;
    AcquireSRWLockShared(&state_lock);
    if (!find_session(handle)) {
        ReleaseSRWLockShared(&state_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!decode_object(object, &certificate_index, &kind)) {
        ReleaseSRWLockShared(&state_lock);
        return CKR_OBJECT_HANDLE_INVALID;
    }
    for (i = 0; i < count; ++i) {
        CK_RV item_result = get_one_attribute(&certificate_store.certificates[certificate_index],
                                              kind, &attributes[i]);
        if (item_result != CKR_OK && result == CKR_OK) result = item_result;
    }
    ReleaseSRWLockShared(&state_lock);
    return result;
}

static CK_RV bridge_C_SignInit(CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                               CK_OBJECT_HANDLE key) {
    bridge_session *session;
    CK_ULONG certificate_index, kind;
    if (!mechanism || mechanism->pParameter || mechanism->ulParameterLen) return CKR_ARGUMENTS_BAD;
    AcquireSRWLockExclusive(&state_lock);
    session = find_session(handle);
    if (!session) {
        ReleaseSRWLockExclusive(&state_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (session->sign_active) {
        ReleaseSRWLockExclusive(&state_lock);
        return CKR_OPERATION_ACTIVE;
    }
    if (!decode_object(key, &certificate_index, &kind) || kind != OBJECT_PRIVATE_KEY) {
        ReleaseSRWLockExclusive(&state_lock);
        return CKR_KEY_HANDLE_INVALID;
    }
    if ((certificate_store.certificates[certificate_index].key_type == CKK_RSA &&
         mechanism->mechanism != CKM_RSA_PKCS) ||
        (certificate_store.certificates[certificate_index].key_type == CKK_EC &&
         mechanism->mechanism != CKM_ECDSA)) {
        ReleaseSRWLockExclusive(&state_lock);
        return CKR_MECHANISM_INVALID;
    }
    session->sign_active = 1;
    session->sign_certificate_index = certificate_index;
    session->sign_mechanism = mechanism->mechanism;
    ReleaseSRWLockExclusive(&state_lock);
    return CKR_OK;
}

static CK_RV bridge_C_Sign(CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG data_len,
                           CK_BYTE_PTR signature, CK_ULONG_PTR signature_len) {
    bridge_session *session;
    const bridge_certificate *entry;
    CK_RV result;
    if (!data || !signature_len) return CKR_ARGUMENTS_BAD;
    AcquireSRWLockExclusive(&state_lock);
    session = find_session(handle);
    if (!session) {
        ReleaseSRWLockExclusive(&state_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!session->sign_active) {
        ReleaseSRWLockExclusive(&state_lock);
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    entry = &certificate_store.certificates[session->sign_certificate_index];
    if (!signature) {
        *signature_len = entry->signature_len;
        ReleaseSRWLockExclusive(&state_lock);
        return CKR_OK;
    }
    if (*signature_len < entry->signature_len) {
        *signature_len = entry->signature_len;
        ReleaseSRWLockExclusive(&state_lock);
        return CKR_BUFFER_TOO_SMALL;
    }
    result = bridge_store_sign(entry, session->sign_mechanism, data, data_len,
                               signature, signature_len);
    session->sign_active = 0;
    ReleaseSRWLockExclusive(&state_lock);
    return result;
}

#define FN(name) ((CK_VOID_PTR)(name))
static CK_FUNCTION_LIST function_list;
static INIT_ONCE function_list_once = INIT_ONCE_STATIC_INIT;

CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR output);

static BOOL CALLBACK prepare_function_list(PINIT_ONCE once, PVOID parameter,
                                           PVOID *context) {
    (void)once;
    (void)parameter;
    (void)context;
    ZeroMemory(&function_list, sizeof(function_list));
    function_list.version.major = 2;
    function_list.version.minor = 40;
    function_list.C_Initialize = FN(bridge_C_Initialize);
    function_list.C_Finalize = FN(bridge_C_Finalize);
    function_list.C_GetInfo = FN(bridge_C_GetInfo);
    function_list.C_GetFunctionList = FN(C_GetFunctionList);
    function_list.C_GetSlotList = FN(bridge_C_GetSlotList);
    function_list.C_GetSlotInfo = FN(bridge_C_GetSlotInfo);
    function_list.C_GetTokenInfo = FN(bridge_C_GetTokenInfo);
    function_list.C_GetMechanismList = FN(bridge_C_GetMechanismList);
    function_list.C_GetMechanismInfo = FN(bridge_C_GetMechanismInfo);
    function_list.C_OpenSession = FN(bridge_C_OpenSession);
    function_list.C_CloseSession = FN(bridge_C_CloseSession);
    function_list.C_CloseAllSessions = FN(bridge_C_CloseAllSessions);
    function_list.C_GetSessionInfo = FN(bridge_C_GetSessionInfo);
    function_list.C_Login = FN(bridge_C_Login);
    function_list.C_Logout = FN(bridge_C_Logout);
    function_list.C_GetAttributeValue = FN(bridge_C_GetAttributeValue);
    function_list.C_FindObjectsInit = FN(bridge_C_FindObjectsInit);
    function_list.C_FindObjects = FN(bridge_C_FindObjects);
    function_list.C_FindObjectsFinal = FN(bridge_C_FindObjectsFinal);
    function_list.C_SignInit = FN(bridge_C_SignInit);
    function_list.C_Sign = FN(bridge_C_Sign);

    function_list.C_InitToken = FN(unsupported);
    function_list.C_InitPIN = FN(unsupported);
    function_list.C_SetPIN = FN(unsupported);
    function_list.C_GetOperationState = FN(unsupported);
    function_list.C_SetOperationState = FN(unsupported);
    function_list.C_CreateObject = FN(unsupported);
    function_list.C_CopyObject = FN(unsupported);
    function_list.C_DestroyObject = FN(unsupported);
    function_list.C_GetObjectSize = FN(unsupported);
    function_list.C_SetAttributeValue = FN(unsupported);
    function_list.C_EncryptInit = FN(unsupported);
    function_list.C_Encrypt = FN(unsupported);
    function_list.C_EncryptUpdate = FN(unsupported);
    function_list.C_EncryptFinal = FN(unsupported);
    function_list.C_DecryptInit = FN(unsupported);
    function_list.C_Decrypt = FN(unsupported);
    function_list.C_DecryptUpdate = FN(unsupported);
    function_list.C_DecryptFinal = FN(unsupported);
    function_list.C_DigestInit = FN(unsupported);
    function_list.C_Digest = FN(unsupported);
    function_list.C_DigestUpdate = FN(unsupported);
    function_list.C_DigestKey = FN(unsupported);
    function_list.C_DigestFinal = FN(unsupported);
    function_list.C_SignUpdate = FN(unsupported);
    function_list.C_SignFinal = FN(unsupported);
    function_list.C_SignRecoverInit = FN(unsupported);
    function_list.C_SignRecover = FN(unsupported);
    function_list.C_VerifyInit = FN(unsupported);
    function_list.C_Verify = FN(unsupported);
    function_list.C_VerifyUpdate = FN(unsupported);
    function_list.C_VerifyFinal = FN(unsupported);
    function_list.C_VerifyRecoverInit = FN(unsupported);
    function_list.C_VerifyRecover = FN(unsupported);
    function_list.C_DigestEncryptUpdate = FN(unsupported);
    function_list.C_DecryptDigestUpdate = FN(unsupported);
    function_list.C_SignEncryptUpdate = FN(unsupported);
    function_list.C_DecryptVerifyUpdate = FN(unsupported);
    function_list.C_GenerateKey = FN(unsupported);
    function_list.C_GenerateKeyPair = FN(unsupported);
    function_list.C_WrapKey = FN(unsupported);
    function_list.C_UnwrapKey = FN(unsupported);
    function_list.C_DeriveKey = FN(unsupported);
    function_list.C_SeedRandom = FN(unsupported);
    function_list.C_GenerateRandom = FN(unsupported);
    function_list.C_GetFunctionStatus = FN(unsupported);
    function_list.C_CancelFunction = FN(unsupported);
    function_list.C_WaitForSlotEvent = FN(unsupported);
    return TRUE;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR output) {
    if (!output) return CKR_ARGUMENTS_BAD;
    if (!InitOnceExecuteOnce(&function_list_once, prepare_function_list, NULL, NULL))
        return CKR_GENERAL_ERROR;
    *output = &function_list;
    return CKR_OK;
}
