#pragma once
#include <filesystem>
#include <vector>
#include <cstdint>

#define CANT_OPEN 300
#define NOT_FILE 400
#define CANT_READ 500

namespace fs = std::filesystem;

bool is_elf(const std::vector<std::uint8_t>& fileData);

bool contains_signature(const std::vector<std::uint8_t>& fileData, const std::vector<std::uint8_t>& signature);

std::vector<std::uint8_t> file_path_to_vector(const fs::path& path);

void scanner(const fs::path& path, const std::vector<std::uint8_t>& signature);

std::vector<uint8_t> extract_signature(const fs::path& path);