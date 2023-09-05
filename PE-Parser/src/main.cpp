/*

author : Yekuuun
github : https://github.com/Yekuuun

*/

#include <iostream>
#include <fstream>
#include <filesystem> 
#include <Windows.h>
#include <string.h>
#include "handlePE.hpp"

LPCWSTR convert_char_wchar(char *path_to_file);

int main(int argc, char *argv[]){

    //gcc compiled code
    #ifdef __i386__
        std::cout << "Not a 64-bit architecture...\n" << std::endl;
        return EXIT_FAILURE;
    #endif

    if(argc != 2){
        std::cout << "choose an argument : <path_to_file.exe>" << std::endl;
        return EXIT_FAILURE;
    }

    //get argument
    char *path_to_file = argv[1];
    
    std::cout << "Loading BasePE... \n" << std::endl;

    LPCWSTR filename = convert_char_wchar(path_to_file);

    //ptr to PE 
    int operation_on_PE = LoadPEFile(filename);

    if(operation_on_PE != 0){
        return EXIT_FAILURE;
    }

    std::cout << "PE operations successfully made !\n" << std::endl;

    return EXIT_SUCCESS;
}

//char* to wchar
LPCWSTR convert_char_wchar(char *path_to_file){
    try
    {
        int filename_length = strlen(path_to_file);

        int wideStringLength = MultiByteToWideChar(CP_UTF8, 0, path_to_file, filename_length, NULL, 0);

        wchar_t* widePath = new wchar_t[wideStringLength + 1];

        MultiByteToWideChar(CP_UTF8, 0, path_to_file, filename_length, widePath, wideStringLength);
        widePath[wideStringLength] = L'\0';

        return (LPCWSTR)widePath;
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        std::cout << "error while trying to open file" << std::endl;
        exit(EXIT_FAILURE);
    }
}