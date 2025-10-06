#define CATCH_CONFIG_MAIN
#include "catch_amalgamated.hpp"
#include "file_scanner.hpp"
#include <vector>
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

TEST_CASE("file_path_to_vector returns empty vector on an empty file", "[file_scanner]") {
    fs::path test_path = "test_files/empty_file.txt";

    std::ofstream ofs(test_path, std::ios::binary);
    REQUIRE(ofs.good());
    ofs.close();

    auto result = file_path_to_vector(test_path);

    REQUIRE(result.empty());

    fs::remove(test_path);
}


TEST_CASE("file_path_to_vector with ELF file", "[file_scanner]") {
    fs::path test_path = "test_files/minimal_elf";

    fs::path cpp_file = "test_files/minimal.cpp";
    {
        std::ofstream ofs(cpp_file);
        REQUIRE(ofs.good());
        ofs << "int main() { return 0; }";
    }

    int ret = system(("g++ -o " + test_path.string() + " " + cpp_file.string()).c_str());
    REQUIRE(ret == 0);
    REQUIRE(fs::exists(test_path));
    REQUIRE(fs::is_regular_file(test_path));
    auto result = file_path_to_vector(test_path);

    REQUIRE(result.size() > 0);

    REQUIRE(result.size() >= 4);
    REQUIRE(result[0] == 0x7f);
    REQUIRE(result[1] == 'E');
    REQUIRE(result[2] == 'L');
    REQUIRE(result[3] == 'F');

    fs::remove(test_path);
    fs::remove(cpp_file);
}

TEST_CASE("is_elf with ELF file", "[file_scanner]"){
    fs::path test_path = "test_files/minimal_elf";

    fs::path cpp_file = "test_files/minimal.cpp";
    {
        std::ofstream ofs(cpp_file);
        REQUIRE(ofs.good());
        ofs << "int main() { return 0; }";
    }

    int ret = system(("g++ -o " + test_path.string() + " " + cpp_file.string()).c_str());
    REQUIRE(ret == 0);
    REQUIRE(fs::exists(test_path));
    REQUIRE(fs::is_regular_file(test_path));
    auto result = file_path_to_vector(test_path);

    REQUIRE(is_elf(result));

    fs::remove(test_path);
    fs::remove(cpp_file);
}

TEST_CASE("is_elf with no file", "[file_scanner]"){
    fs::path test_path = "test_files/empty_file.txt";

    std::ofstream ofs(test_path, std::ios::binary);
    REQUIRE(ofs.good());
    ofs << "int main() { return 0; }";
    ofs.close();

    auto result = file_path_to_vector(test_path);

    REQUIRE(!is_elf(result));

    fs::remove(test_path);
}

void insert_signature(const fs::path& path, const std::vector<uint8_t>& sig, std::streampos offset = 0) {
    std::fstream file(path, std::ios::in | std::ios::out | std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file for writing signature");
    }

    file.seekp(offset);
    if (!file) {
        throw std::runtime_error("Failed to seek to position in file");
    }

    file.write(reinterpret_cast<const char*>(sig.data()), sig.size());
    if (!file) {
        throw std::runtime_error("Failed to write signature to file");
    }
}


TEST_CASE("contains_signature with inserted signature", "[file_scanner]") {

    fs::path test_path = "test_files/contaminated";
    fs::path cpp_file = "test_files/contaminated.cpp";

    {
        std::ofstream ofs(cpp_file);
        REQUIRE(ofs.good());
        ofs << "int main() { return 0; }";
    }

    int ret = system(("g++ -o " + test_path.string() + " " + cpp_file.string()).c_str());
    REQUIRE(ret == 0);
    REQUIRE(fs::exists(test_path));
    REQUIRE(fs::is_regular_file(test_path));

    std::vector<uint8_t> sig = {0xDE, 0xAD, 0xBE, 0xEF}; 
    insert_signature(test_path, sig, 100);

    auto result = file_path_to_vector(test_path);
    REQUIRE(contains_signature(result, sig));

    fs::remove(test_path);
    fs::remove(cpp_file);
}

TEST_CASE("contains_signature when the file does not have the signature", "[file_scanner]") {

    fs::path test_path = "test_files/contaminated";
    fs::path cpp_file = "test_files/contaminated.cpp";

    {
        std::ofstream ofs(cpp_file);
        REQUIRE(ofs.good());
        ofs << "int main() { return 0; }";
    }

    int ret = system(("g++ -o " + test_path.string() + " " + cpp_file.string()).c_str());
    REQUIRE(ret == 0);
    REQUIRE(fs::exists(test_path));
    REQUIRE(fs::is_regular_file(test_path));

    std::vector<uint8_t> sig = {0xDE, 0xAD, 0xBE, 0xEF}; 
    //insert_signature(test_path, sig, 100);

    auto result = file_path_to_vector(test_path);
    REQUIRE(!contains_signature(result, sig));

    fs::remove(test_path);
    fs::remove(cpp_file);
}