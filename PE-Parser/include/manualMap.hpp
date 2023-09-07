#ifndef MANUAL_MAP_H
#define MANUAL_MAP_H
#include <Windows.h>

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

//memory mapping
BYTE* read_pe_file(LPCWSTR filename);
BYTE* allocate_size_map_image(PIMAGE_NT_HEADERS nt);
void manual_map(BYTE* image, BYTE *rawPE, PIMAGE_NT_HEADERS nt);
bool relocate(BYTE* image, PIMAGE_NT_HEADERS nt, FIELD_PTR newImgBase);

#endif