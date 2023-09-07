/*

author : Yekuuun
github : https://github.com/Yekuuun

*/

#include <iostream>
#include <string.h>
#include "utils.hpp"

//MAIN MESSAGE
void display_pe_parser(){
    // Code ANSI pour définir la couleur de texte en rose
    std::cout << "\033[1;35m";
    
    // Texte à afficher
    std::cout << "    ____   ______     ____   ___    ____  _____ ___________" << std::endl;
    std::cout << "   / __ \\ / ____/    / __  \\/   |  / __ \\/ ___//  ____/ __ \\" << std::endl;
    std::cout << "  / /_/  / __/______/ /_/  / /| | / /_/ /\\__ \\/ __ /   /_/ /" << std::endl;
    std::cout << " / ____ / /__/_____/ ____ / ___ |/ _, _/___/ / /___ / _, _/" << std::endl;
    std::cout << "/_/    /_____/    /_/    /_/  |_/_/ |_|/____/_____ /_/ |_|" << std::endl;

    
    // Réinitialiser la couleur de texte à la normale
    std::cout << "\033[0m";
    std::cout << "\n\n" << std::endl;
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