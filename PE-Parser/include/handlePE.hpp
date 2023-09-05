#ifndef HANDLEPE_H
#define HANDLEPE_H
#include <Windows.h>

int LoadPEFile(LPCWSTR filename);
PIMAGE_NT_HEADERS get_nt_hdr(BYTE* loadPE);
bool get_loaded_imports(BYTE* baseAddress, PIMAGE_NT_HEADERS nt);

#ifdef _WIN64
typedef ULONG_PTR FIELD_PTR;
#else
typedef  DWORD_PTR FIELD_PTR;
#endif

#endif