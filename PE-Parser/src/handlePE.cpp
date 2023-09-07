/*

author : Yekuuun
github : https://github.com/Yekuuun

*/
#include <iostream>
#include <Windows.h>
#include <vector>
#include "handlePE.hpp"
#include "manualMap.hpp"

//--------------------------------PE MANIPULATION----------------------------------------

int LoadPEFile(LPCWSTR filename){

    //get ptr to PE base address in memory
    BYTE* PEBaseAddress = read_pe_file(filename);
    if(PEBaseAddress == NULL){
        return 1;
    }

    //nt header ptr
    PIMAGE_NT_HEADERS nt_header = get_nt_hdr(PEBaseAddress);
    if(nt_header == NULL){
        return 1;
    }

    BYTE* image_address = allocate_size_map_image(nt_header);
    if(image_address == NULL){
        return 1;
    }

    //manual map
    manual_map(image_address, PEBaseAddress, nt_header);
    if (!relocate(image_address, nt_header, (FIELD_PTR)image_address)) {
        std::cerr << "Relocating image has failed\n";
        return 1;
    }

    //dos header
    get_dos_header_infos(PEBaseAddress);

    //data directories
    get_data_directories_infos(nt_header);

    //file header
    get_nt_header_infos(nt_header);

    //loaded DLL's
    if(!get_loaded_imports(image_address, nt_header)){
        std::cout << "No imports founded...\n" << std::endl;
    }

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

    IMAGE_DATA_DIRECTORY importsDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if(importsDir.VirtualAddress == 0){
        return false;
    }

    std::cout << "\n\n---------------DLL IMPORTS-----------------\n" << std::endl;
    //go to IMPORT DESCRIPTOR
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDir.VirtualAddress + (FIELD_PTR)baseAddress);

    std::cout << "Loaded DLL's & functions : " << std::endl;
    while(importDescriptor->Name != NULL){
        LPCSTR libraryName = (LPCSTR)(importDescriptor->Name + (FIELD_PTR)baseAddress);
        std::cout << "Library name :" << libraryName << std::endl;

        //functions
        PIMAGE_THUNK_DATA ptr_thunk = (PIMAGE_THUNK_DATA)((FIELD_PTR)baseAddress + importDescriptor->FirstThunk);

        std::cout << "Functions : \n" << std::endl;
        while(ptr_thunk->u1.AddressOfData != NULL){
            PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)((FIELD_PTR)baseAddress + ptr_thunk->u1.AddressOfData);
            LPCSTR functionName = (LPCSTR)import_by_name->Name;
            std::cout << functionName << std::endl;
            ptr_thunk++;
        }

        importDescriptor++;
    }

    std::cout << "\n---------------DLL IMPORTS-----------------\n" << std::endl;
    return true;
}

//FILE HEADER INFORMATIONS
void get_nt_header_infos(PIMAGE_NT_HEADERS nt){

    IMAGE_FILE_HEADER ptr_file_header = (IMAGE_FILE_HEADER)nt->FileHeader;
    IMAGE_OPTIONAL_HEADER ptr_optional_header = (IMAGE_OPTIONAL_HEADER)nt->OptionalHeader;

    std::cout << "\n\n---------------NT HEADER INFOS-----------------\n" << std::endl;

    std::cout << "PE file signature : " << std::hex << nt->Signature << std::endl;

    std::cout << "\nFILE HEADER : " << std::endl;
    std::cout << std::hex << "Machine : " << ptr_file_header.Machine << std::endl;
    std::cout << std::hex << "Sections count : " << ptr_file_header.NumberOfSections << std::endl;
    std::cout << std::hex << "Timestamp : " << ptr_file_header.TimeDateStamp << std::endl;
    std::cout << std::hex << "Size optionnal header : " << ptr_file_header.SizeOfOptionalHeader << "\n" << std::endl;

    std::cout << "OPTIONNAL HEADER : " << std::endl;
    std::cout << "Magic: " << std::hex << ptr_optional_header.Magic << std::endl;
    std::cout << "MajorLinkerVersion: " << static_cast<int>(ptr_optional_header.MajorLinkerVersion) << std::endl;
    std::cout << "MinorLinkerVersion: " << static_cast<int>(ptr_optional_header.MinorLinkerVersion) << std::endl;
    std::cout << "SizeOfCode: " << ptr_optional_header.SizeOfCode << std::endl;
    std::cout << "SizeOfInitializedData: " << ptr_optional_header.SizeOfInitializedData << std::endl;
    std::cout << "SizeOfUninitializedData: " << ptr_optional_header.SizeOfUninitializedData << std::endl;
    std::cout << "AddressOfEntryPoint: " << ptr_optional_header.AddressOfEntryPoint << std::endl;
    std::cout << "BaseOfCode: " << ptr_optional_header.BaseOfCode << std::endl;
    std::cout << "ImageBase: " << ptr_optional_header.ImageBase << std::endl;
    std::cout << "SectionAlignment: " << ptr_optional_header.SectionAlignment << std::endl;
    std::cout << "FileAlignment: " << ptr_optional_header.FileAlignment << std::endl;
    std::cout << "MajorOperatingSystemVersion: " << ptr_optional_header.MajorOperatingSystemVersion << std::endl;
    std::cout << "MinorOperatingSystemVersion: " << ptr_optional_header.MinorOperatingSystemVersion << std::endl;
    std::cout << "MajorImageVersion: " << ptr_optional_header.MajorImageVersion << std::endl;
    std::cout << "MinorImageVersion: " << ptr_optional_header.MinorImageVersion << std::endl;
    std::cout << "MajorSubsystemVersion: " << ptr_optional_header.MajorSubsystemVersion << std::endl;
    std::cout << "MinorSubsystemVersion: " << ptr_optional_header.MinorSubsystemVersion << std::endl;
    std::cout << "Win32VersionValue: " << ptr_optional_header.Win32VersionValue << std::endl;
    std::cout << "SizeOfImage: " << ptr_optional_header.SizeOfImage << std::endl;
    std::cout << "SizeOfHeaders: " << ptr_optional_header.SizeOfHeaders << std::endl;
    std::cout << "CheckSum: " << ptr_optional_header.CheckSum << std::endl;
    std::cout << "Subsystem: " << ptr_optional_header.Subsystem << std::endl;
    std::cout << "DllCharacteristics: " << ptr_optional_header.DllCharacteristics << std::endl;
    std::cout << "SizeOfStackReserve: " << ptr_optional_header.SizeOfStackReserve << std::endl;
    std::cout << "SizeOfStackCommit: " << ptr_optional_header.SizeOfStackCommit << std::endl;
    std::cout << "SizeOfHeapReserve: " << ptr_optional_header.SizeOfHeapReserve << std::endl;
    std::cout << "SizeOfHeapCommit: " << ptr_optional_header.SizeOfHeapCommit << std::endl;
    std::cout << "LoaderFlags: " << ptr_optional_header.LoaderFlags << std::endl;
    std::cout << "NumberOfRvaAndSizes: " << ptr_optional_header.NumberOfRvaAndSizes << std::endl;

    std::cout << "\n---------------NT HEADER INFOS-----------------\n" << std::endl;
}

//get directories data
void get_data_directories_infos(PIMAGE_NT_HEADERS nt){

    std::cout << "\n---------------DATA DIRECTORIES INFOS-----------\n" << std::endl;

    IMAGE_DATA_DIRECTORY exportsDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_DATA_DIRECTORY importsDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if(exportsDir.VirtualAddress == 0){
        std::cout << "No export directories \n";
    }

    else {
        std::cout << "EXPORT DIR :" << std::endl;
        std::cout << "RVA : " << std::hex << exportsDir.VirtualAddress << std::endl;
        std::cout << "Size : " << std::hex << exportsDir.Size << std::endl;
    }

    if(importsDir.VirtualAddress == 0){
        std::cout << "No import directories \n";
    }

    else {
        std::cout << "\nIMPORT DIR :" << std::endl;
        std::cout << "RVA : " << std::hex << importsDir.VirtualAddress << std::endl;
        std::cout << "Size : " << std::hex << importsDir.Size << std::endl;
    }

    std::cout << "\n---------------DATA DIRECTORIES INFOS-----------\n" << std::endl;
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
