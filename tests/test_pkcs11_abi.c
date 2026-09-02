#include <windows.h>
#include <stdio.h>

#include "pkcs11.h"

#if defined(_WIN64)
_Static_assert(sizeof(CK_ULONG) == 4, "PKCS#11 CK_ULONG must be 32-bit on Windows");
_Static_assert(sizeof(CK_FUNCTION_LIST) == 552, "Unexpected 64-bit CK_FUNCTION_LIST layout");
#else
_Static_assert(sizeof(CK_ULONG) == 4, "PKCS#11 CK_ULONG must be 32-bit on Windows");
_Static_assert(sizeof(CK_FUNCTION_LIST) == 276, "Unexpected 32-bit CK_FUNCTION_LIST layout");
#endif

typedef CK_RV (__cdecl *get_function_list_fn)(CK_FUNCTION_LIST_PTR_PTR);
typedef CK_RV (__cdecl *initialize_fn)(CK_VOID_PTR);
typedef CK_RV (__cdecl *finalize_fn)(CK_VOID_PTR);
typedef CK_RV (__cdecl *get_info_fn)(CK_INFO_PTR);
typedef CK_RV (__cdecl *get_slot_list_fn)(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR);
typedef CK_RV (__cdecl *get_mechanism_list_fn)(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR);
typedef CK_RV (__cdecl *get_mechanism_info_fn)(CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR);
typedef CK_RV (__cdecl *open_session_fn)(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_VOID_PTR,
                                         CK_SESSION_HANDLE_PTR);

static int failures;
#define CHECK(expr) do { if (!(expr)) { \
    fwprintf(stderr, L"FAIL line %d: %S\n", __LINE__, #expr); \
    ++failures; \
} } while (0)

int wmain(int argc, wchar_t **argv) {
    HMODULE module;
    get_function_list_fn get_function_list;
    union {
        FARPROC generic;
        get_function_list_fn typed;
    } loader;
    CK_FUNCTION_LIST_PTR functions = NULL;
    CK_INFO info;
    CK_ULONG count = 0;
    CK_MECHANISM_TYPE mechanisms[2];
    CK_MECHANISM_INFO mechanism_info;
    CK_SESSION_HANDLE session = 0;
    CK_RV result;

    if (argc != 2) {
        fwprintf(stderr, L"Usage: test-pkcs11-abi.exe <pkcs11-dll>\n");
        return 2;
    }
    module = LoadLibraryW(argv[1]);
    if (!module) {
        fwprintf(stderr, L"LoadLibrary failed: %lu\n", GetLastError());
        return 2;
    }
    loader.generic = GetProcAddress(module, "C_GetFunctionList");
    get_function_list = loader.typed;
    CHECK(get_function_list != NULL);
    if (!get_function_list) { FreeLibrary(module); return 1; }
    CHECK(get_function_list(&functions) == CKR_OK);
    CHECK(functions != NULL);
    CHECK(functions && functions->version.major == 2 && functions->version.minor == 40);
    CHECK(functions && functions->C_Initialize && functions->C_Finalize);
    CHECK(functions && functions->C_GetSlotList && functions->C_GetAttributeValue);
    CHECK(functions && functions->C_FindObjectsInit && functions->C_Sign);
    if (!functions) { FreeLibrary(module); return 1; }

    result = ((initialize_fn)functions->C_Initialize)(NULL);
    CHECK(result == CKR_OK);
    if (result == CKR_OK) {
        CHECK(((get_info_fn)functions->C_GetInfo)(&info) == CKR_OK);
        CHECK(info.cryptokiVersion.major == 2 && info.cryptokiVersion.minor == 40);
        CHECK(((get_slot_list_fn)functions->C_GetSlotList)(CK_FALSE, NULL, &count) == CKR_OK);
        CHECK(count == 1);
        count = 2;
        CHECK(((get_mechanism_list_fn)functions->C_GetMechanismList)(1, mechanisms, &count) == CKR_OK);
        CHECK(count == 2 && mechanisms[0] == CKM_RSA_PKCS && mechanisms[1] == CKM_ECDSA);
        CHECK(((get_mechanism_info_fn)functions->C_GetMechanismInfo)(
            1, CKM_RSA_PKCS, &mechanism_info) == CKR_OK);
        CHECK((mechanism_info.flags & CKF_SIGN) != 0);
        CHECK(((open_session_fn)functions->C_OpenSession)(
            999, CKF_SERIAL_SESSION, NULL, NULL, &session) == CKR_SLOT_ID_INVALID);
        CHECK(((finalize_fn)functions->C_Finalize)(NULL) == CKR_OK);
    }
    FreeLibrary(module);
    if (failures) return 1;
    puts("PKCS#11 ABI tests passed");
    return 0;
}
