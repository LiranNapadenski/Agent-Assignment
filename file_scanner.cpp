#include "file_scanner.hpp"

#include <filesystem>
#include <vector>
#include <cstdint>
#include <fstream>
#include <iostream>

namespace fs = std::filesystem;

bool is_elf(const std::vector<std::uint8_t>& fileData) {
    if (fileData.size() < 4) return false;
    return fileData[0] == 0x7F && fileData[1] == 'E' && fileData[2] == 'L' && fileData[3] == 'F';
}

std::vector<std::uint8_t> file_path_to_vector(const fs::path& path){

    std::vector<std::uint8_t> fileData;

    if(!fs::is_regular_file(path)){
        std::cerr << "path does not point to a file" << "\n";
        throw NOT_FILE;
    }

    std::ifstream file(path, std::ifstream::binary | std::ifstream::ate);
    
    if (!file){
        std::cerr << "could not open file" << "\n";
        throw CANT_OPEN;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> fileData;
    if(!file.read(reinterpret_cast<char*>(fileData.data()), size)){
        std::cerr << "could not read" << "\n";
    }

    return fileData;
}