#ifndef HANDLEPE_H
#define HANDLEPE_H
#include <Windows.h>

//macros
#ifdef _WIN64
typedef ULONG_PTR FIELD_PTR;
#else
typedef  DWORD_PTR FIELD_PTR;
#endif

#define RELOC_32BIT_FIELD 3
#define RELOC_64BIT_FIELD 0xA

#ifdef _WIN64
#define RELOC_FIELD RELOC_64BIT_FIELD
typedef ULONG_PTR FIELD_PTR;
#else
#define RELOC_FIELD RELOC_32BIT_FIELD
typedef  DWORD_PTR FIELD_PTR;
#endif

typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY;

//main function
int LoadPEFile(LPCWSTR filename);

//memory mapping
BYTE* read_pe_file(LPCWSTR filename);
BYTE* allocate_size_map_image(PIMAGE_NT_HEADERS nt);
void manual_map(BYTE* image, BYTE *rawPE, PIMAGE_NT_HEADERS nt);
bool relocate(BYTE* image, PIMAGE_NT_HEADERS nt, FIELD_PTR newImgBase);

//PE manipulation
PIMAGE_NT_HEADERS get_nt_hdr(BYTE* loadPE);
bool get_loaded_imports(BYTE* baseAddress, PIMAGE_NT_HEADERS nt);
void get_nt_header_infos(PIMAGE_NT_HEADERS nt);
void get_data_directories_infos(PIMAGE_NT_HEADERS nt);
void get_dos_header_infos(BYTE* baseAddress);

#endif