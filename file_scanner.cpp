#include "file_scanner.hpp"

#include <filesystem>
#include <vector>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <iostream>
#include <deque>

namespace fs = std::filesystem;

bool is_elf(const std::vector<std::uint8_t>& fileData) {
    if (fileData.size() < 4) return false;
    return fileData[0] == 0x7F && fileData[1] == 'E' && fileData[2] == 'L' && fileData[3] == 'F';
}

std::vector<std::uint8_t> extract_sig(const fs::path& path){

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
        throw CANT_READ;
    }

    return fileData;
}

bool contains_signature(const fs::path& path, const std::vector<std::uint8_t>& signature){
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
    if(size < 4){
        std::clog << "not an elf file";
        return false;
    }
    file.seekg(0, std::ios::beg);

    //check if elf
    std::vector<std::uint8_t> elfBuffer;
    elfBuffer.resize(4);
    if(!file.read(reinterpret_cast<char*>(elfBuffer.data()), 4)){
        std::cerr << "could not read" << "\n";
        throw CANT_READ;
    }
    if( !is_elf(elfBuffer)){
        return false;
    }

    //the idea is so read chuncks from the file and search in each of them using the build in search function ,
    // also there have to be a overlap between chunks to not miss the signiture
    std::size_t buffer_size  = 8 * 1024 * 1024; //8Mb chuncks
    std::vector<std::uint8_t> buffer(buffer_size );
    auto bm_searcher  = std::boyer_moore_searcher(signature.begin(), signature.end());
    const std::size_t overlap = signature.size() - 1;

    while (file) {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize bytes_read = file.gcount();
        if (bytes_read <= 0) break; // EOF or read error

        auto it = std::search(buffer.begin(), buffer.begin() + bytes_read, bm_searcher);
        if (it != buffer.begin() + bytes_read) {
            return true;
        }

        // last chunk
        if (bytes_read < static_cast<std::streamsize>(buffer_size)) break;

        //return to scann the overlap between to chunks
        if (!file.seekg(-static_cast<std::streamoff>(overlap), std::ios::cur)) {
            std::cerr << "seekg failed\n";
            throw CANT_READ;
        }
    }

    return false; // not found
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

    if(contains_signature(root, signature)){
        std::cout << root.string() << " is infected!" << "\n";
    }

    return;
}