#include "file_scanner.hpp"
#include <iostream>
#include <filesystem>
#include <vector>



namespace fs = std::filesystem;


int main(int argc, char* argv[]){


    //handling the input a bit

    if(argc !=3){
        std::cout << "please enter the root directory path" << "\n";
        std::cout << "please enter the sig file's path" << "\n";
    }
    
    const fs::path root(argv[1]);
    const fs::path sigFile(argv[2]);

    if(!fs::exists(root)){
        std::cout << "the root path you entered does not exists" << "\n";
    }

    if(!fs::exists(sigFile)){
        std::cout << "the sig file's path path you entered does not exists" << "\n";
    }

    std::vector<uint8_t> signiture ;

    try{
        signiture = file_path_to_vector(sigFile);
    }
    catch(int eNum){

        if(CANT_OPEN == eNum){
            std::cout << "could\'nt open the signitarue file" << "\n";
        }
        else if(NOT_FILE == eNum){
            std::cout << "the given signitarue file's path does not pint to a file" << "\n";
        }
        else if(CANT_READ == eNum){
            std::cout << "could\'nt read from the signitarue file" << "\n";
        }
        return 1;
    }
    catch(...){

        std::cout << "an unexpected error as accured" << "\n";
        return 1;
    }

    //starting the scanner
    std::cout << "scanning" << "\n";
    
    scanner(root, signiture);

    return 0;
}