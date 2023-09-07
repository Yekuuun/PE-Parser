/*

author : Yekuuun
github : https://github.com/Yekuuun

*/
#include <iostream>
#include "manualMap.hpp"

//-------------------------------MAP PE TO MEMORY--------------------------------

//read PE file
BYTE* read_pe_file(LPCWSTR filename){
    HANDLE hFile;

    //get handle to file.
    hFile = CreateFileW(
        filename,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if(hFile == INVALID_HANDLE_VALUE){
        DWORD lastError = GetLastError();
        lastError == 2 ? std::cout << "File not found \n" << std::endl : std::cout << "Unable to get handle to file with error : " << lastError << "\n" << std::endl;
        return NULL;
    }

    //file size
    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return NULL;
    }

    //read the file
    BYTE* rawPE = new BYTE[size];
    if (!ReadFile(hFile, rawPE, size, NULL, NULL)) {
        std::cerr << "[ERROR] Reading the file has failed!\n";
        delete[]rawPE;
        rawPE = NULL;
    }

    CloseHandle(hFile);

    //ptr to PE
    return rawPE;
}

//map sections
BYTE* allocate_size_map_image(PIMAGE_NT_HEADERS nt){
    
    BYTE* image = (BYTE*)VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE ,PAGE_READWRITE);

    if(image == NULL){
        std::cerr << "[ERROR] Unable to map sections into memory\n";
        return NULL;
    }

    return image;
}

//mapping sections
void manual_map(BYTE* image, BYTE *rawPE, PIMAGE_NT_HEADERS nt){
    memcpy(image, rawPE, nt->OptionalHeader.SizeOfHeaders);

    // map sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {

        memcpy((BYTE*)(image)+section[i].VirtualAddress, (BYTE*)(rawPE)+section[i].PointerToRawData, section[i].SizeOfRawData);
    }
}

//relocating -> thanks to Hasherezade
bool relocate(BYTE* image, PIMAGE_NT_HEADERS nt, FIELD_PTR newImgBase){
    IMAGE_DATA_DIRECTORY relocationsDirectory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocationsDirectory.VirtualAddress == 0) {
        return false;
    }

    PIMAGE_BASE_RELOCATION ProcessBReloc = (PIMAGE_BASE_RELOCATION)(relocationsDirectory.VirtualAddress + (FIELD_PTR)image);
    // apply relocations:
    while (ProcessBReloc->VirtualAddress != 0)
    {
        DWORD page = ProcessBReloc->VirtualAddress;

        if (ProcessBReloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            size_t count = (ProcessBReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            BASE_RELOCATION_ENTRY* list = (BASE_RELOCATION_ENTRY*)(LPWORD)(ProcessBReloc + 1);

            for (size_t i = 0; i < count; i++)
            {
                if (list[i].Type & RELOC_FIELD)
                {
                    DWORD rva = list[i].Offset + page;

                    PULONG_PTR p = (PULONG_PTR)((LPBYTE)image + rva);
                    //relocate the address
                    *p = ((*p) - nt->OptionalHeader.ImageBase) + (FIELD_PTR)newImgBase;
                }
            }
        }
        ProcessBReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)ProcessBReloc + ProcessBReloc->SizeOfBlock);
    }
    return true;
}
