#include "functions.h"
#include "md5.h"
#include "md5.cpp"

namespace fs = std::filesystem;
MD5 md5;

//file names vector
std::vector<std::string> getFileNames(char* pathToFiles) {

    std::vector<std::string> fileNames;

    for (const auto& entry : fs::directory_iterator(pathToFiles)) {

        std::string inputFILE = entry.path().generic_string();
        //std::cout << inputFILE << std::endl;
        fileNames.push_back(inputFILE);

    }

    return fileNames;
}

//keys vector
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

//read inputFILE, encryption for keyLine, write to encryptFILE
std::string process_ENC(char* inputFILE, char* encryptFILE, char* keyLine) {

    int blocks_number = 0; //Number of full blocks
    int incomplete_blocks_number = 0; //Number of incomplete blocks 
    AES_block* inputBlocks = new AES_block; // Blocks
    BYTE iv[16]; //Init vector (if CBC)

    /* ----- Encryption ----- */

    readBlocksFromFile(inputFILE, inputBlocks, blocks_number, incomplete_blocks_number);

    std::string hash = md5(inputBlocks, blocks_number);

    AES_block* encryptedBlocks = AES_Encrypt(keyLine, inputBlocks, blocks_number, iv, incomplete_blocks_number);
    writeBlocksToFile(encryptFILE, encryptedBlocks, blocks_number, incomplete_blocks_number);

    return hash;
}

//read encryptFILE, decryption for keyLine, write to decryptFILE
std::string process_DEC(char* encryptFILE, char* decryptFILE, char* keyLine, std::vector<std::string> &hashes) {

    int blocks_number = 0; //Number of full blocks
    int incomplete_blocks_number = 0; //Number of incomplete blocks 
    AES_block* inputBlocks = new AES_block; // Blocks
    BYTE iv[16]; //Init vector (if CBC)

    /* ----- Decryption ----- */

    readBlocksFromFile(encryptFILE, inputBlocks, blocks_number, incomplete_blocks_number);
    AES_block* decryptedBlocks = AES_Decrypt(keyLine, inputBlocks, blocks_number, iv, incomplete_blocks_number);

    std::string hash = md5(decryptedBlocks, blocks_number);

    //write only good files to directory
    auto iter = std::find(hashes.begin(), hashes.end(), hash);
    if (iter != hashes.end() ) {
        writeBlocksToFile(decryptFILE, decryptedBlocks, blocks_number, incomplete_blocks_number);
        hashes.erase(iter);
        return hash;
    }
    else {
        return "badhash";
    }
        
}

void shuffle(std::vector<std::string> &vec) {
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(vec.begin(), vec.end(), g);
}

//fill number of keys to numer of files
void fillKeys(std::vector<std::string>& keys, int number) {
    std::vector<std::string> tempKeys;
    srand(unsigned(time(0)));
    for (int i = 0; i < number; i++) {
        if (i >= keys.size()) { 
            tempKeys.push_back(keys[rand() % (keys.size())]);
        }
        else { tempKeys.push_back(keys[i]); }
    }
    keys = tempKeys;
}

//clear decrypted & encryted folders;
void deleteDirectoryContents(char* dir)
{
    for (const auto& entry : fs::directory_iterator(dir)) {
        fs::remove_all(entry.path());
    }
}

int main() {

    //Settings

    char* pathToFiles = "files";
    char* pathToKeyFile = "keys.txt";

    std::vector<std::string> keys = getKeys(pathToKeyFile);
    std::vector<std::string> fileNames = getFileNames(pathToFiles);
    std::vector<std::string> fileHashes;

    std::cout << "Files in directory: " << fileNames.size() << std::endl;
    std::cout << "Keys in file: " << keys.size() << std::endl;

    //clear dirs
    deleteDirectoryContents("decrypted");
    deleteDirectoryContents("encrypted");

    if (keys.size() == 0 || fileNames.size() == 0) { return 0; }
    if (keys.size() < fileNames.size()) { fillKeys(keys, fileNames.size()); }

    //Mix
    shuffle(keys);

    std::cout << std::endl << " ----- Encrypt ----- " << std::endl << std::endl;

    //Encryption for all files
    for (int i = fileNames.size() - 1; i >= 0; --i) {

        char* inputFILE = fileNames[i].data();

        std::string encFilePath = fileNames[i]; 
        encFilePath.erase(0, encFilePath.find_first_of("/"));
        encFilePath.erase(encFilePath.find_last_of("."), encFilePath.size() - 1);
        encFilePath = "encrypted" + encFilePath + ".bin";
        char* encryptFILE = encFilePath.data();

        char* keyLine = reinterpret_cast<char*>(keys[i].data());

        std::string hash_INP = process_ENC(inputFILE, encryptFILE, keyLine);
        fileHashes.push_back(hash_INP);

        std::cout << i << ") \tHASH_INP: " << hash_INP << " | KEY: " << keyLine << std::endl;

    }

    //Mix
    shuffle(keys);
    shuffle(fileNames);

    std::cout << std::endl << " ----- Decrypt ----- " << std::endl << std::endl;

    //Decryption
    for (int i = fileNames.size() - 1; i >= 0; --i) {

        std::string encFilePath = fileNames[i]; 
        encFilePath.erase(0, encFilePath.find_first_of("/"));
        encFilePath.erase(encFilePath.find_last_of("."), encFilePath.size() - 1);
        encFilePath = "encrypted" + encFilePath + ".bin";
        char* encryptFILE = encFilePath.data();

        std::string decFilePath = fileNames[i]; 
        decFilePath.erase(0, decFilePath.find_first_of("/"));
        decFilePath = "decrypted" + decFilePath;
        char* decryptFILE = decFilePath.data();

        for (int j = keys.size() - 1; j >= 0; --j) {

            char* keyLine = reinterpret_cast<char*>(keys[j].data());

            std::string hash_DEC = process_DEC(encryptFILE, decryptFILE, keyLine, fileHashes);

            if (hash_DEC != "badhash") {
                std::cout << i << ") \tHASH_DEC: " << hash_DEC << " | KEY: " << keyLine << std::endl;
            }

        }

    }

}
