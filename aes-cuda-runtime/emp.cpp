#include "functions.h"

int main() {

    //Вводимая строка
    char* inputLine = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Minus repellat debitis possimus, ipsa doloribus quos ipsum, laboriosam quia at sapiente culpa iusto enim, voluptatem deserunt dignissimos! Ipsa sit rerum, totam.";
    std::cout << "Input line: " << inputLine << std::endl;

    //Ключ
    char* keyLine = "0123456789abcdef";
    std::cout << "Key: " << keyLine << std::endl;

    AES_block * encryptedLine = AES_Encrypt(keyLine, inputLine);
    AES_block * decryptedLine = AES_Decrypt(keyLine, reinterpret_cast<char*>(encryptedLine));


}