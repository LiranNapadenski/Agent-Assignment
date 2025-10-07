#include "file_scanner.hpp"

#include <filesystem>
#include <vector>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <iostream>

namespace fs = std::filesystem;

bool is_elf(const std::vector<std::uint8_t>& fileData) {
    if (fileData.size() < 4) return false;
    return fileData[0] == 0x7F && fileData[1] == 'E' && fileData[2] == 'L' && fileData[3] == 'F';
}

std::vector<std::uint8_t> file_path_to_vector(const fs::path& path){

    std::vector<std::uint8_t> fileData;

    if(!fs::is_regular_file(path) || !fs::exists(path)){
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
    fileData.resize(size);
    if(!file.read(reinterpret_cast<char*>(fileData.data()), size)){
        std::cerr << "could not read" << "\n";
    }

    return fileData;
}

bool contains_signature(const std::vector<std::uint8_t>& fileData, const std::vector<std::uint8_t>& signature){
    auto it = std::search(fileData.begin(), fileData.end(), signature.begin(), signature.end());
    return it != fileData.end();
}

void scanner(const fs::path& root, const std::vector<std::uint8_t>& signature){

    if(!fs::exists(root)){
        return;
    }

    if(fs::is_directory(root)){
        for(auto const& entry : fs::directory_iterator(root)){
            scanner(entry.path(), signature);
        }
        return;
    }

    std::vector<uint8_t> rootData = file_path_to_vector(root);

    if(!is_elf(rootData)) return;

    if(contains_signature(rootData, signature)){
        std::cout << root.string() << " is infected!" << "\n";
    }

    return;
}