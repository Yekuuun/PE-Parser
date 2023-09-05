#ifndef HANDLEPE_H
#define HANDLEPE_H
#include <Windows.h>

//prototypes
int LoadPEFile(LPCWSTR filename);
PIMAGE_NT_HEADERS get_nt_hdr(BYTE* loadPE);
bool get_loaded_imports(BYTE* baseAddress, PIMAGE_NT_HEADERS nt);
void get_file_header_infos(PIMAGE_NT_HEADERS nt);
void get_dos_header_infos(BYTE* baseAddress);
void display_pe_parser();


#ifdef _WIN64
typedef ULONG_PTR FIELD_PTR;
#else
typedef  DWORD_PTR FIELD_PTR;
#endif

#endif