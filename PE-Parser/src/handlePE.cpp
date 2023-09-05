/*

author : Yekuuun
github : https://github.com/Yekuuun

*/
#include <iostream>
#include <Windows.h>
#include <vector>
#include "handlePE.hpp"

int LoadPEFile(LPCWSTR filename){

    //params
    HANDLE hFileMapping;
    HANDLE hFile;
    LPVOID lpFileBase;

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
        return 1;
    }

    hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if ( hFileMapping == 0 )
    {   
        std::cout << "Couldn't open file mapping with CreateFileMapping() with error : "<< GetLastError() << "\n" << std::endl;
        goto CLEANUP;
    }
    
    //map file into memory
    lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if ( lpFileBase == 0 )
    {
        std::cout << "Couldn't map file into memory with error : " << GetLastError() << "\n" << std::endl;
        goto CLEANUP;
    }

    //BYTE ptr
    BYTE* PEBaseAddress = (BYTE*)lpFileBase;

    //nt header
    PIMAGE_NT_HEADERS nt_header = get_nt_hdr(PEBaseAddress);

    if(nt_header == NULL){
        goto CLEANUP;
    }

    //display PE informations :
    std::cout << "----------------------------PE INFORMATIONS------------------------\n" << std::endl;

    /*if(!get_loaded_imports(PEBaseAddress, nt_header)){
        std::cout << "No imports founded...\n" << std::endl;
    }*/

    goto SUCCESS;

    
    CLEANUP:
        if(hFile){
            CloseHandle(hFile);
        }

        if(hFileMapping){
            CloseHandle(hFileMapping);
        }

        if(lpFileBase){
            UnmapViewOfFile(lpFileBase);
        }
        return 1;

    SUCCESS:
        UnmapViewOfFile(lpFileBase);
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return 0;
}

//get NT_HEADER address
PIMAGE_NT_HEADERS get_nt_hdr(BYTE* loadPE)
{
    //DOS HEADER
    IMAGE_DOS_HEADER* DOSHeader = (PIMAGE_DOS_HEADER)loadPE;
    if (DOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cout << "Not a PE file" << std::endl;
        return NULL;
    }

    //get NT header base address
    PIMAGE_NT_HEADERS nt = PIMAGE_NT_HEADERS((char*)(loadPE)+DOSHeader->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        std::cout << "Not a PE file" << std::endl;
        return NULL;
    }

    std::cout << "NT HEADER base address in memory : " << nt << "\n" << std::endl;
    return nt;
}

//get loaded imports
bool get_loaded_imports(BYTE* baseAddress, PIMAGE_NT_HEADERS nt){

    //go to import directory
    IMAGE_DATA_DIRECTORY importsDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if(importsDir.VirtualAddress == 0){
        return false;
    }

    //go to IMAGE_IMPORT_DESCRIPTOR adding address of data directory virtualAddress + file base address in memory to get to correct start address of struct
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDir.VirtualAddress + (FIELD_PTR)baseAddress);


    //on each DLL
    while(importDescriptor->Name != NULL){
        std::cout << "Loaded DLL's : \n" << std::endl;
        LPCSTR libraryName = (LPCSTR)((FIELD_PTR)baseAddress + importDescriptor->Name);
        std::cout << "Library : " << libraryName << "\n" << std::endl;
        importDescriptor++;
    }

    return true;
}