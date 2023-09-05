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

    //loaded DLL's
    if(!get_loaded_imports(PEBaseAddress, nt_header)){
        std::cout << "No imports founded...\n" << std::endl;
    }

    //dos header
    get_dos_header_infos(PEBaseAddress);

    //file header
    get_file_header_infos(nt_header);

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

    //ptr to FileHeader
    return nt;
}

//get loaded imports

bool get_loaded_imports(BYTE* baseAddress, PIMAGE_NT_HEADERS nt){

    //go to import directory
    PIMAGE_DATA_DIRECTORY importsDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if(importsDir->VirtualAddress == NULL){
        return false;
    }

    //go to IMAGE_IMPORT_DESCRIPTOR adding address of data directory virtualAddress + file base address in memory to get to correct start address of struct
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDir->VirtualAddress + (FIELD_PTR)baseAddress);


    //on each DLL
    while(importDescriptor->Name != NULL){
        std::cout << "Loaded DLL's : \n" << std::endl;
        LPCSTR libraryName = (LPCSTR)((FIELD_PTR)baseAddress + importDescriptor->Name);
        std::cout << "Library : " << libraryName << "\n" << std::endl;
        importDescriptor++;
    }

    return true;
}

//FILE HEADER INFORMATIONS
void get_file_header_infos(PIMAGE_NT_HEADERS nt){


    IMAGE_FILE_HEADER ptr_file_header = (IMAGE_FILE_HEADER)nt->FileHeader;

    //display informations
    std::cout << "---------------FILE HEADER INFOS---------------- \n" << std::endl;
    std::cout << std::hex << "Machine : " << ptr_file_header.Machine << std::endl;
    std::cout << std::hex << "Sections count : " << ptr_file_header.NumberOfSections << std::endl;
    std::cout << std::hex << "Timestamp : " << ptr_file_header.TimeDateStamp << std::endl;
    std::cout << std::hex << "Size optionnal header : " << ptr_file_header.SizeOfOptionalHeader << std::endl;
    std::cout << "\n---------------FILE HEADER INFOS-----------------" << std::endl;
}

//DOS HEADER INFORMATIONS
void get_dos_header_infos(BYTE* baseAddress){

    IMAGE_DOS_HEADER* dos_header = (PIMAGE_DOS_HEADER)baseAddress;
    
    std::cout << "---------------DOS HEADER INFOS---------------- \n" << std::endl;
    std::cout << std::hex << "Magic number : " << dos_header->e_magic  <<std::endl;
    std::cout << std::hex << "Bytes last page : " << dos_header->e_cblp <<std::endl;
    std::cout << std::hex << "Pages in file : " << dos_header->e_cp <<std::endl;
    std::cout << std::hex << "Relocations : " << dos_header->e_crlc  <<std::endl;
    std::cout << std::hex << "Size header in paragraph : " << dos_header->e_cparhdr  <<std::endl;
    std::cout << std::hex << "Min extra paragraph : " << dos_header->e_minalloc  <<std::endl;
    std::cout << std::hex << "Max extra paragraph" << dos_header->e_maxalloc <<std::endl;
    std::cout << std::hex << "initial SS value :" << dos_header->e_ss  <<std::endl;
    std::cout << std::hex << "Initial SP value : " << dos_header->e_sp  <<std::endl;
    std::cout << std::hex << "Checksum : " << dos_header->e_csum <<std::endl;
    std::cout << std::hex << "Initial IP value :" << dos_header->e_ip  <<std::endl;
    std::cout << std::hex << "initial CS value :" << dos_header->e_cs  <<std::endl;
    std::cout << std::hex << "File address relocation table :" << dos_header->e_lfarlc  <<std::endl;
    std::cout << "\n---------------DOS HEADER INFOS-----------------\n" << std::endl;

}
