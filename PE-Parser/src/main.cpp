/*

author : Yekuuun
github : https://github.com/Yekuuun

*/

#include <iostream>
#include <Windows.h>
#include "handlePE.hpp"
#include "utils.hpp"

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
    
    LPCWSTR filename = convert_char_wchar(path_to_file);

    //pe parser
    display_pe_parser();

    //ptr to PE 
    int operation_on_PE = LoadPEFile(filename);

    if(operation_on_PE != 0){
        return EXIT_FAILURE;
    }

    std::cout << "\033[1;35m";
    std::cout << "PE operations successfully made !\n" << std::endl;
    std::cout << "\033[0m";

    return EXIT_SUCCESS;
}


