#include "functions.h"

int main() {

    char* inputFILE = "input.txt"; //Исходный файл
    char* encryptFILE = "encrypt.bin"; //Зашифрованный файл
    char* decryptFILE = "decrypt.txt"; //Расшифрованный файл

    int blocks_number; //Число блоков
    int incomplete_blocks_number; //Число неполных блоков  
    AES_block* inputBlocks = new AES_block; // Блоки

    /* ----- Ключ ----- */

    //Если требуется ключ из файла, то модифицируйте функцию getKey() или же просто передавайте ключи построчно
    char* keyLine = "0123456789abcdef";

    /* ----- Шифрование ----- */

    readBlocksFromFile(inputFILE, inputBlocks, blocks_number, incomplete_blocks_number);
    AES_block* encryptedBlocks = AES_Encrypt(keyLine, inputBlocks, blocks_number, incomplete_blocks_number);
    writeBlocksToFile(encryptFILE, encryptedBlocks, blocks_number, incomplete_blocks_number);
    
    /* ----- Расшифрование ----- */

    readBlocksFromFile(encryptFILE, inputBlocks, blocks_number, incomplete_blocks_number);
    AES_block* decryptedBlocks = AES_Decrypt(keyLine, inputBlocks, blocks_number, incomplete_blocks_number);
    writeBlocksToFile(decryptFILE, decryptedBlocks, blocks_number, incomplete_blocks_number);

}