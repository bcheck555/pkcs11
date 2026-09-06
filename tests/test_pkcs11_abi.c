#include <windows.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include "pkcs11.h"

#if defined(_WIN64)
_Static_assert(sizeof(CK_ULONG) == 4, "PKCS#11 CK_ULONG must be 32-bit on Windows");
_Static_assert(sizeof(CK_FUNCTION_LIST) == 546, "Unexpected packed 64-bit CK_FUNCTION_LIST layout");
#else
_Static_assert(sizeof(CK_ULONG) == 4, "PKCS#11 CK_ULONG must be 32-bit on Windows");
_Static_assert(sizeof(CK_FUNCTION_LIST) == 274, "Unexpected packed 32-bit CK_FUNCTION_LIST layout");
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

#define FUNCTION_LIST_THREADS 16
#define FUNCTION_LIST_REPEATS 1000

typedef struct function_list_worker {
    get_function_list_fn get_list;
    HANDLE start;
    HANDLE ready;
    volatile LONG *ready_count;
    CK_FUNCTION_LIST_PTR functions;
    CK_FUNCTION_LIST snapshot;
} function_list_worker;

static int complete_function_list(const CK_FUNCTION_LIST *functions) {
    size_t offset;
    if (functions->version.major != 2 || functions->version.minor != 40) return 0;
    /* The packed ABI table contains only CK_VOID_PTR entries after version. */
    for (offset = offsetof(CK_FUNCTION_LIST, C_Initialize);
         offset < sizeof(*functions); offset += sizeof(CK_VOID_PTR)) {
        CK_VOID_PTR entry;
        memcpy(&entry, (const unsigned char *)functions + offset, sizeof(entry));
        if (!entry) return 0;
    }
    return 1;
}

static DWORD WINAPI get_function_list_worker(LPVOID parameter) {
    function_list_worker *worker = (function_list_worker *)parameter;
    unsigned int i;
    if (InterlockedIncrement(worker->ready_count) == FUNCTION_LIST_THREADS)
        if (!SetEvent(worker->ready)) return 1;
    if (WaitForSingleObject(worker->start, 10000) != WAIT_OBJECT_0) return 1;
    if (worker->get_list(&worker->functions) != CKR_OK || !worker->functions) return 1;
    memcpy(&worker->snapshot, worker->functions, sizeof(worker->snapshot));
    if (!complete_function_list(&worker->snapshot)) return 1;
    for (i = 0; i < FUNCTION_LIST_REPEATS; ++i) {
        CK_FUNCTION_LIST_PTR functions = NULL;
        if (worker->get_list(&functions) != CKR_OK || functions != worker->functions ||
            memcmp(functions, &worker->snapshot, sizeof(worker->snapshot)) != 0)
            return 1;
        if (((get_function_list_fn)functions->C_GetFunctionList)(&functions) != CKR_OK ||
            functions != worker->functions) return 1;
    }
    return 0;
}

static void test_concurrent_function_list(get_function_list_fn get_list) {
    HANDLE threads[FUNCTION_LIST_THREADS];
    function_list_worker workers[FUNCTION_LIST_THREADS];
    volatile LONG ready_count = 0;
    unsigned int count = 0, i;
    HANDLE start = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(start != NULL && ready != NULL);
    if (!start || !ready) {
        if (start) CloseHandle(start);
        if (ready) CloseHandle(ready);
        return;
    }
    ZeroMemory(workers, sizeof(workers));
    for (i = 0; i < FUNCTION_LIST_THREADS; ++i) {
        workers[i].get_list = get_list;
        workers[i].start = start;
        workers[i].ready = ready;
        workers[i].ready_count = &ready_count;
        threads[i] = CreateThread(NULL, 0, get_function_list_worker, &workers[i], 0, NULL);
        CHECK(threads[i] != NULL);
        if (!threads[i]) break;
        ++count;
    }
    if (count == FUNCTION_LIST_THREADS)
        CHECK(WaitForSingleObject(ready, 10000) == WAIT_OBJECT_0);
    CHECK(SetEvent(start));
    for (i = 0; i < count; ++i) {
        DWORD exit_code = 1;
        DWORD wait_result = WaitForSingleObject(threads[i], 10000);
        CHECK(wait_result == WAIT_OBJECT_0);
        /* Never unload the DLL or release worker storage while a thread runs. */
        if (wait_result != WAIT_OBJECT_0) ExitProcess(1);
        CHECK(GetExitCodeThread(threads[i], &exit_code));
        CHECK(exit_code == 0);
        CHECK(workers[i].functions == workers[0].functions);
        CHECK(memcmp(&workers[i].snapshot, &workers[0].snapshot,
                     sizeof(workers[i].snapshot)) == 0);
        CloseHandle(threads[i]);
    }
    CloseHandle(ready);
    CloseHandle(start);
}

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
    CK_FUNCTION_LIST snapshot;

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
    /* No call into the DLL precedes the synchronized first-call race test. */
    test_concurrent_function_list(get_function_list);
    CHECK(get_function_list(NULL) == CKR_ARGUMENTS_BAD);
    CHECK(get_function_list(&functions) == CKR_OK);
    CHECK(functions != NULL);
    CHECK(functions && functions->version.major == 2 && functions->version.minor == 40);
    CHECK(functions && functions->C_Initialize && functions->C_Finalize);
    CHECK(functions && functions->C_GetSlotList && functions->C_GetAttributeValue);
    CHECK(functions && functions->C_FindObjectsInit && functions->C_Sign);
    if (!functions) { FreeLibrary(module); return 1; }
    memcpy(&snapshot, functions, sizeof(snapshot));

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
        {
            CK_FUNCTION_LIST_PTR after_finalize = NULL;
            CHECK(get_function_list(&after_finalize) == CKR_OK);
            CHECK(after_finalize == functions);
            CHECK(memcmp(functions, &snapshot, sizeof(snapshot)) == 0);
        }
    }
    FreeLibrary(module);
    if (failures) return 1;
    puts("PKCS#11 ABI tests passed");
    return 0;
}
