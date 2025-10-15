#define CATCH_CONFIG_MAIN
#include "catch_amalgamated.hpp"
#include "file_scanner.hpp"
#include <vector>
#include <filesystem>
#include <fstream>
#include <string>
#include <iostream>
#include <sstream>

namespace fs = std::filesystem;

TEST_CASE("extract_sig returns empty vector on an empty file", "[file_scanner]") {
    fs::path test_path = "test_files/empty_file.txt";

    std::ofstream ofs(test_path, std::ios::binary);
    REQUIRE(ofs.good());
    ofs.close();

    auto result = extract_sig(test_path);

    REQUIRE(result.empty());

    fs::remove(test_path);
}


TEST_CASE("extract_sig with ELF file", "[file_scanner]") {
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
    auto result = extract_sig(test_path);

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
    auto result = extract_sig(test_path);

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

    auto result = extract_sig(test_path);

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
    REQUIRE(contains_signature(test_path, sig));

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
    REQUIRE(!contains_signature(test_path, sig));

    fs::remove(test_path);
    fs::remove(cpp_file);
}

TEST_CASE("extract_sig on a sig file", "[file_scanner]") {
    fs::path sig_path = "test_files/test_signature.sig";

    std::vector<std::uint8_t> signature = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};

    {
        std::ofstream ofs(sig_path, std::ios::binary);
        REQUIRE(ofs.good());
        ofs.write(reinterpret_cast<const char*>(signature.data()), signature.size());
        ofs.close();
    }

    std::vector<std::uint8_t> result = extract_sig(sig_path);

    REQUIRE(result.size() == signature.size());
    REQUIRE(std::equal(result.begin(), result.end(), signature.begin()));

    fs::remove(sig_path);
}

TEST_CASE("scanner prints infected ELF files and std::cout is redirected", "[file_scanner]") {

    fs::path root_dir = "test_scanner_root";
    fs::path sub_dir  = root_dir / "subdir";
    fs::create_directories(sub_dir);


    std::vector<std::uint8_t> signature = {0xDE, 0xAD, 0xBE, 0xEF};


    fs::path infected_root = root_dir / "infected_root";
    {
        std::ofstream ofs(infected_root, std::ios::binary);
        REQUIRE(ofs.good());

        std::vector<std::uint8_t> data = {
            0x7F, 'E', 'L', 'F', // ELF header
            0x01, 0x02,           
            0xDE, 0xAD, 0xBE, 0xEF, // Signature embedded
            0x04, 0x05
        };
        ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
    }


    fs::path infected_sub = sub_dir / "infected_sub";
    {
        std::ofstream ofs(infected_sub, std::ios::binary);
        REQUIRE(ofs.good());

        std::vector<std::uint8_t> data = {
            0x7F, 'E', 'L', 'F', // ELF header
            0x10, 0x11,
            0xDE, 0xAD, 0xBE, 0xEF, // Signature embedded
            0x12
        };
        ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
    }


    fs::path clean_file = root_dir / "clean";
    {
        std::ofstream ofs(clean_file, std::ios::binary);
        REQUIRE(ofs.good());

        std::vector<std::uint8_t> data = {
            0x7F, 'E', 'L', 'F', // ELF header
            0x00, 0x01, 0x02, 0x03
        };
        ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
    }


    std::ostringstream captured;
    std::streambuf* oldCoutBuf = std::cout.rdbuf(captured.rdbuf());

    // RAII guard to restore std::cout even if test fails/throws
    struct CoutRestore {
        std::streambuf* buf;
        ~CoutRestore() { std::cout.rdbuf(buf); }
    } restore{oldCoutBuf};

    // Run scanner
    try {
        scanner(root_dir, signature);
    }
    catch (int code) {
        FAIL("Caught int exception with value: " + std::to_string(code));
    }
    catch (...) {
        FAIL("Unknown non-std::exception caught");
    }

    // Get captured output
    std::string out = captured.str();

    std::string expected1 = infected_root.string() + " is infected!\n";
    std::string expected2 = infected_sub.string()  + " is infected!\n";
    std::string unexpected = clean_file.string()  + " is infected!\n";

    INFO("Captured output:\n" << out);
    REQUIRE(out.find(expected1) != std::string::npos);
    REQUIRE(out.find(expected2) != std::string::npos);
    REQUIRE(out.find(unexpected) == std::string::npos);

    // Cleanup
    fs::remove_all(root_dir);
}

TEST_CASE("Full program test", "[find_sig]") {

    fs::path root_dir = "test_full_program_root";
    fs::create_directories(root_dir);


    fs::path sub_dir = root_dir / "subdir";
    fs::create_directories(sub_dir);

    fs::path sub_dir_empty = root_dir / "subdir_empty";
    fs::create_directories(sub_dir_empty);

    // Create a signature file
    fs::path sig_file = "test_signature.sig";
    {
        std::ofstream ofs(sig_file, std::ios::binary);
        REQUIRE(ofs.good());
        std::vector<uint8_t> signature = {0xDE, 0xAD, 0xBE, 0xEF};
        ofs.write(reinterpret_cast<const char*>(signature.data()), signature.size());
    }


    fs::path infected_file = root_dir / "infected.bin";
    {
        std::ofstream ofs(infected_file, std::ios::binary);
        REQUIRE(ofs.good());

        std::vector<std::uint8_t> data = {
            0x7F, 'E', 'L', 'F', // ELF header
            0x01, 0x02,
            0xDE, 0xAD, 0xBE, 0xEF, // Signature embedded
            0x04, 0x05
        };
        ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
    }


    fs::path infected_sub = sub_dir / "infected_sub.bin";
    {
        std::ofstream ofs(infected_sub, std::ios::binary);
        REQUIRE(ofs.good());

        std::vector<std::uint8_t> data = {
            0x7F, 'E', 'L', 'F', // ELF header
            0xAA, 0xBB,
            0xDE, 0xAD, 0xBE, 0xEF, // Signature embedded
            0xCC, 0xDD
        };
        ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
    }


    fs::path clean_file = root_dir / "clean.bin";
    {
        std::ofstream ofs(clean_file, std::ios::binary);
        REQUIRE(ofs.good());

        std::vector<std::uint8_t> data = {
            0x7F, 'E', 'L', 'F', // ELF header
            0x01, 0x02,
            0x04, 0x05
        };
        ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
    }

    // Run the program
    std::string command = "./find_sig " + root_dir.string() + " " + sig_file.string();
    FILE* pipe = popen(command.c_str(), "r");
    REQUIRE(pipe != nullptr);

    char buffer[128];
    std::ostringstream output;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output << buffer;
    }
    int ret_code = pclose(pipe);
    REQUIRE(ret_code == 0);

    std::string program_output = output.str();

    // Check that infected files were detected
    REQUIRE(program_output.find(infected_file.string() + " is infected!") != std::string::npos);
    REQUIRE(program_output.find(infected_sub.string() + " is infected!") != std::string::npos);

    // Check that clean file was not reported
    REQUIRE(program_output.find(clean_file.string() + " is infected!") == std::string::npos);

    // Cleanup
    fs::remove_all(root_dir);
    fs::remove(sig_file);
}

TEST_CASE("non-ELF files containing signature are not detected", "[file_scanner][integration]") {
    fs::path root_dir = "test_nonelf_root";
    fs::create_directories(root_dir);

    std::vector<std::uint8_t> signature = {0xDE, 0xAD, 0xBE, 0xEF};

    //Create a non-ELF file that contains the signature
    fs::path nonelf = root_dir / "infected_nonelf.bin";
    {
        std::ofstream ofs(nonelf, std::ios::binary);
        REQUIRE(ofs.good());
        // start with some bytes that are NOT ELF magic
        std::vector<std::uint8_t> data = {
            0x10, 0x11, 0x12, 0x13,
            0xDE, 0xAD, 0xBE, 0xEF, // signature embedded
            0x20, 0x21
        };
        ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
    }

    //Create an ELF-like file that contains the signature
    fs::path elf_file = root_dir / "infected_elf";
    {
        std::ofstream ofs(elf_file, std::ios::binary);
        REQUIRE(ofs.good());
        std::vector<std::uint8_t> data = {
            0x7F, 'E', 'L', 'F',     // ELF magic
            0x01, 0x02,
            0xDE, 0xAD, 0xBE, 0xEF, // signature embedded
            0x03
        };
        ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
    }

    //Create a clean ELF file that does NOT contain the signature
    fs::path clean_elf = root_dir / "clean_elf";
    {
        std::ofstream ofs(clean_elf, std::ios::binary);
        REQUIRE(ofs.good());
        std::vector<std::uint8_t> data = {
            0x7F, 'E', 'L', 'F',
            0x00, 0x01, 0x02
        };
        ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
    }

    // Redirect std::cout to capture scanner output
    std::ostringstream captured;
    std::streambuf* oldCoutBuf = std::cout.rdbuf(captured.rdbuf());

    struct CoutRestore {
        std::streambuf* buf;
        ~CoutRestore(){ std::cout.rdbuf(buf); }
    } restore{oldCoutBuf};

    // Run scanner 
    try {
        scanner(root_dir, signature);
    } catch (int code) {
        FAIL("Caught int exception with value: " + std::to_string(code));
    } catch (const std::exception& e) {
        FAIL(std::string("std::exception: ") + e.what());
    } catch (...) {
        FAIL("Unknown non-std::exception caught");
    }

    // get captured output
    std::string out = captured.str();

    std::string expected_elf = elf_file.string() + " is infected!";
    std::string unexpected_nonelf = nonelf.string() + " is infected!";
    std::string unexpected_clean = clean_elf.string() + " is infected!";

    INFO("Captured output:\n" << out);
    // ELF file must be present
    REQUIRE(out.find(expected_elf) != std::string::npos);
    // non-ELF file must NOT be present
    REQUIRE(out.find(unexpected_nonelf) == std::string::npos);
    // clean ELF (no signature) must NOT be present
    REQUIRE(out.find(unexpected_clean) == std::string::npos);

    // Cleanup
    fs::remove_all(root_dir);
}


TEST_CASE("Program handles GB infected file", "[integration]") {

    fs::path root_dir = "test_gb_file_root";
    fs::create_directories(root_dir);


    fs::path sig_file = "gb_signature.sig";
    std::vector<uint8_t> signature = {0xDE, 0xAD, 0xBE, 0xEF};
    {
        std::ofstream ofs(sig_file, std::ios::binary);
        REQUIRE(ofs.good());
        ofs.write(reinterpret_cast<const char*>(signature.data()), signature.size());
    }

    fs::path infected_file = root_dir / "huge_infected.bin";
    {
        std::ofstream ofs(infected_file, std::ios::binary);
        REQUIRE(ofs.good());

        // Write ELF header
        uint8_t elf_header[4] = {0x7F, 'E', 'L', 'F'};
        ofs.write(reinterpret_cast<const char*>(elf_header), 4);

        // Write 20GB of filler using repeated blocks to avoid huge memory allocation
        const size_t block_size = 1024 * 1024; // 1 MB block
        const size_t total_size = 1024ULL * 1024ULL * 1024ULL * 20; //20gb
        std::vector<uint8_t> block(block_size, 0xAA);

        // Write GB minus a few MB, then insert the signature
        size_t bytes_written = 0;
        while (bytes_written + block_size < total_size - 10 * 1024 * 1024) {
            ofs.write(reinterpret_cast<const char*>(block.data()), block.size());
            bytes_written += block_size;
        }

        // Write the signature near the end
        ofs.write(reinterpret_cast<const char*>(signature.data()), signature.size());

        // Add some trailing bytes
        ofs.put(0x00);
        ofs.put(0xFF);
    }

    // Run
    std::string command = "./find_sig " + root_dir.string() + " " + sig_file.string();
    FILE* pipe = popen(command.c_str(), "r");
    REQUIRE(pipe != nullptr);

    char buffer[256];
    std::ostringstream output;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output << buffer;
    }

    int ret_code = pclose(pipe);
    REQUIRE(ret_code == 0);

    std::string out = output.str();

    // Check that the infected file was detected
    REQUIRE(out.find(infected_file.string() + " is infected!") != std::string::npos);

    // Cleanup
    fs::remove_all(root_dir);
    fs::remove(sig_file);
}
