#include "Header.h"

int main()
{
    AEScipher path("key.txt", "folder");
    //unsigned char* encfile;
    
    std::cout << "Writing keys to a file" << std::endl;
    //Delete empty string
    // Remove '\0' from the end of the string
    for (auto& vec : path.keyss) {
        vec.erase(std::remove(vec.begin(), vec.end(), '\0'), vec.end());
    }

    // Remove empty strings (after removal)
    path.keyss.erase(std::remove_if(path.keyss.begin(), path.keyss.end(), [](const auto& vec) {
        return vec.empty();
    }), path.keyss.end());

    // Remove '\0' from the end of the string
    for (auto& vec : path.files) {
        vec.erase(std::remove(vec.begin(), vec.end(), '\0'), vec.end());
    }

    // Remove empty strings (after removal)
    path.files.erase(std::remove_if(path.files.begin(), path.files.end(), [](const auto& vec) {
        return vec.empty();
    }), path.files.end());

    std::vector<unsigned char> combinedData;
    for (const auto& key : path.keyss) {
        combinedData.insert(combinedData.end(), key.begin(), key.end());
    }
    
    // Write the combined data to a file
    path.WriteFile(combinedData, "keysEncript.bin");

    std::cout << "Combined data written to output_combined.bin" << std::endl;

    path.files.erase(std::remove_if(path.files.begin(), path.files.end(), [](const auto& vec) {
        return vec.empty();
    }), path.files.end());

    std::cout << "Writing data to files: " << std::endl;

    for (std::size_t i = 0; i < path.files.size(); ++i) {
        std::string filename = "dataEncode/fileEncript" + std::to_string(i) + ".bin";
        path.WriteFile(path.files[i], filename);
        std::cout << "Data written to " << filename << std::endl;
    }

    std::cout << std::endl << "data file: " << std::endl;

    std::cout << "key: ";

    for (int i = 0; path.key[i] != '\0'; ++i) {
        std::cout << "Character at index " << i << ": " << path.key[i] << std::endl;
    }

    std::cout << "file: " << std::endl;

    for (int i = 0; path.file[i] != '\0'; ++i) {
        std::cout << "Character at index " << i << ": " << path.file[i] << std::endl;
    }

    path.WriteFile(path.key, "C:/Users/Anastasia/Desktop/GPU_file_encryption/GPU_file_encryption/GPU_file_encryption/keyforcheck.bin");

    // read file
    std::vector<char> filestr = path.ReadFile("C:/Users/Anastasia/Desktop/GPU_file_encryption/GPU_file_encryption/GPU_file_encryption/keyforcheck.bin");

    for (char c : filestr) {
        std::cout << c;
    }

    return 0;
}