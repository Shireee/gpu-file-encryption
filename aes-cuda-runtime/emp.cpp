#include "functions.h"

int main() {

    char* inputFILE = "files/input.txt"; //Исходный файл
    char* encryptFILE = "files/encrypt.bin"; //Зашифрованный файл
    char* decryptFILE = "files/decrypt.txt"; //Расшифрованный файл

    int blocks_number = 0; //Число блоков
    int incomplete_blocks_number = 0; //Число неполных блоков  
    AES_block* inputBlocks = new AES_block; // Блоки
    BYTE iv[16]; //Вектор инициализации

    /* ----- Ключ ----- */

    //Если требуется ключ из файла, то модифицируйте функцию getKey() или же просто передавайте ключи построчно
    char* keyLine = "0123456789abcdef";

    /* ----- Шифрование ----- */

    readBlocksFromFile(inputFILE, inputBlocks, blocks_number, incomplete_blocks_number);
    AES_block* encryptedBlocks = AES_Encrypt(keyLine, inputBlocks, blocks_number, iv,incomplete_blocks_number);
    writeBlocksToFile(encryptFILE, encryptedBlocks, blocks_number, incomplete_blocks_number);
    
    /* ----- Расшифрование ----- */

    readBlocksFromFile(encryptFILE, inputBlocks, blocks_number, incomplete_blocks_number);
    AES_block* decryptedBlocks = AES_Decrypt(keyLine, inputBlocks, blocks_number, iv, incomplete_blocks_number);
    writeBlocksToFile(decryptFILE, decryptedBlocks, blocks_number, incomplete_blocks_number);

}