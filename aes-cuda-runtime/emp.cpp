#include "functions.h"

namespace fs = std::filesystem;

//Вектор с именами файлов
std::vector<std::string> getFileNames(char* pathToFiles) {

    std::vector<std::string> fileNames;

    for (const auto& entry : fs::directory_iterator(pathToFiles)) {

        std::string inputFILE = entry.path().generic_string();
        std::cout << inputFILE << std::endl;
        fileNames.push_back(inputFILE);

    }

    return fileNames;
}

//Вектор со всеми ключами
std::vector<std::string > getKeys(char* pathToKeyFile) {

    std::vector<std::string> allKeys;
    std::string key;
    std::ifstream file(pathToKeyFile);

    while (getline(file, key)) {
        allKeys.push_back(key);
    }

    file.close();

    return allKeys;
}

int main() {

    //Настройки

    char* pathToFiles = "files";
    char* pathToKeyFile = "keys.txt";

    std::vector<std::string> keys = getKeys(pathToKeyFile);
    std::vector<std::string> fileNames = getFileNames(pathToFiles);

    for (int i = 0; i < keys.size(); i++) {

        std::string inputFilePath = fileNames[i]; //Исходный файл

        std::string encFilePath = fileNames[i]; //Шифрованный файл
        encFilePath.erase(0, encFilePath.find_first_of("/"));
        encFilePath.erase(encFilePath.find_last_of("."), encFilePath.size() - 1);
        encFilePath = "encrypted/" + encFilePath + ".bin";

        std::string decFilePath = fileNames[i]; //Дешифрованный файл
        decFilePath.erase(0, decFilePath.find_first_of("/"));
        decFilePath = "decrypted/" + decFilePath;

        char* inputFILE = inputFilePath.data();
        char* encryptFILE = encFilePath.data();
        char* decryptFILE = decFilePath.data();

        int blocks_number = 0; //Число блоков
        int incomplete_blocks_number = 0; //Число неполных блоков  
        AES_block* inputBlocks = new AES_block; // Блоки
        BYTE iv[16]; //Вектор инициализации

        /* ----- Ключ ----- */

        char* keyLine = reinterpret_cast<char *>(keys[i].data());

        /* ----- Шифрование ----- */

        readBlocksFromFile(inputFILE, inputBlocks, blocks_number, incomplete_blocks_number);
        AES_block* encryptedBlocks = AES_Encrypt(keyLine, inputBlocks, blocks_number, iv, incomplete_blocks_number);
        writeBlocksToFile(encryptFILE, encryptedBlocks, blocks_number, incomplete_blocks_number);

        /* ----- Расшифрование ----- */

        readBlocksFromFile(encryptFILE, inputBlocks, blocks_number, incomplete_blocks_number);
        AES_block* decryptedBlocks = AES_Decrypt(keyLine, inputBlocks, blocks_number, iv, incomplete_blocks_number);
        writeBlocksToFile(decryptFILE, decryptedBlocks, blocks_number, incomplete_blocks_number);

    }

}
