#include "Header.h"
#include <fstream>
#include <filesystem>
#include <sstream>
#include <algorithm> // Для std::shuffle
#include <random>    // Для std::random_device и std::mt19937
#include "md5.h"

namespace fs = std::filesystem;


int Padding(int fileSize)
{
    return static_cast<size_t>(std::pow(2, std::ceil(std::log2(fileSize))));
}


void AEScipher::Shuffer(size_t len_key)
{
    std::random_device rd;
    std::mt19937 g(rd());

    std::shuffle(keyss.begin(), keyss.end(), g);

}

// The constructor of the class. Reading files and directories
AEScipher::AEScipher(std::string pathkey, std::string folder)
{
    std::vector<unsigned char> keyforcopy;
    keyforcopy = ReadFile(pathkey);

    std::vector<unsigned char> emtyLine;
    for (unsigned char ch : keyforcopy) {
        if (ch == '\n') {
            keyss.push_back(emtyLine);
            emtyLine.clear();
        }
        else {
            emtyLine.push_back(ch);
            
        }
    }

    if (!emtyLine.empty()) {
        keyss.push_back(emtyLine);

    }

    for (int i = 0; i < keyss.size(); i++) {
        if (keyss[i].size() % 16 != 0) {
            PadKey(keyss[i]);
        }
    }


    for (const auto& entry : fs::directory_iterator(folder)) {


        std::string filename = entry.path().generic_string();
        std::vector<unsigned char> fileContent = ReadFile(filename);

        if (!fileContent.empty()) {

            std::vector<unsigned char> unsignedFileContent(fileContent.begin(), fileContent.end());

            files.push_back(std::move(unsignedFileContent));
        }
    }
}


void AEScipher::PrintDataFiles(const std::vector<std::vector<unsigned char>>& files)
{
    int number_file_to_read = 0;
    for (const auto& row : files) {
        std::cout << "Data read " << number_file_to_read << " : ";
        for (const auto& element : row) {
            std::cout << static_cast<int>(element) << " ";
        }
        std::cout << "check1" << std::endl;
        number_file_to_read++;
    }
}

void AEScipher::PrintKey(const std::vector<unsigned char> vec)
{
    std::cout << "Data in keys: ";
    for (unsigned char data : vec) {
        std::cout << static_cast<int>(data )<< " ";
    }
    std::cout << std::endl;
}

void AEScipher::WriteFile(std::vector<unsigned char > writedata, const std::string path)
{
    std::ofstream outFile(path, std::ios::binary);

    if (!outFile.is_open()) {
        std::cerr << "Unable to open the file." << std::endl;
    }

    size_t lastIndex = writedata.size() - 1;
    while (lastIndex >= 0 && writedata[lastIndex] == '\0') {
        lastIndex--;
    }
    if (lastIndex >= 0) {
        outFile.write(reinterpret_cast<const char*>(writedata.data()), lastIndex + 1);
    }

    outFile.close();
}




// read one file
std::vector<unsigned char> AEScipher::ReadFile(std::string path) {
    std::ifstream inputFile(path, std::ios::binary);

    if (!inputFile.is_open()) {
        std::cerr << "Unable to open the file." << std::endl;
        return std::vector<unsigned char>();
    }

    inputFile.seekg(-1, std::ios::end);
    int size = inputFile.tellg();
   
    int len = Padding(size + 1);


    std::vector<unsigned char> buffer(len);

    inputFile.seekg( 0 -(size + 1), std::ios::end);


    
    inputFile.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

    inputFile.close();

    
    return buffer;
}

void AEScipher::PadKey(std::vector<unsigned char>& addKey)
{
    const size_t AES_BLOCK_SIZE = 16;

    size_t remainder = AES_BLOCK_SIZE - (addKey.size() % AES_BLOCK_SIZE);

    if (remainder != 0) {
        addKey.resize(addKey.size() + remainder, 0);
    }
}

void AEScipher::CheckSumsMD5(std::vector<unsigned char> data)
{

    MD5 md5;

    std::string strData(data.begin(), data.end());
    hash.push_back( md5(strData.c_str(), strData.length()));

}

void AEScipher::MemoryCleaning()
{


    std::vector<std::vector<std::vector<unsigned char>>*> vectorsToClear = { &keyss, &files, &filesEncript, &filesDescript };

    for (auto vecPtr : vectorsToClear) {
        for (auto& vec : *vecPtr) {
            vec.clear();
        }
        vecPtr->clear();
    }

}



void AEScipher::RotWord(unsigned char* a)
{
    unsigned char c = a[0];
    a[0] = a[1];
    a[1] = a[2];
    a[2] = a[3];
    a[3] = c;
}


void AEScipher::SubWord(unsigned char* a)
{
    for (int i = 0; i < 4; i++) {
        a[i] = sBox[a[i] / 16][a[i] % 16];
    }
}

void AEScipher::Round(unsigned char* a, unsigned int n)
{
    unsigned int i;
    unsigned char c = 1;
    for (i = 0; i < n - 1; i++) {
        c = field(c);
    }

    a[0] = c;
    a[1] = a[2] = a[3] = 0;
}

unsigned char AEScipher::field(unsigned char b)
{
    return  (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}

void AEScipher::InvSbox()
{

    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 16; ++j) {
            unsigned char original_value = sBox[i][j];
            invSbox[original_value / 16][original_value % 16] = i * 16 + j;
        }
    }
}

void AEScipher::Xor(unsigned char* a, unsigned char* b, unsigned char* c)
{
    int i;
    for (i = 0; i < 4; i++) {
        c[i] = a[i] ^ b[i];
    }
}

// key expansion
void AEScipher::keyExpansion(const unsigned char key[], unsigned char w[]) {
    unsigned char temp[4];
    unsigned char rcon[4];

    size_t i = 0;
    while (i < 4 * Nk) {
        w[i] = key[i];
        i++;
    }

    i = 4 * Nk;
    while (i < 4 * Nb * (Nr + 1)) {
        temp[0] = w[i - 4 + 0];
        temp[1] = w[i - 4 + 1];
        temp[2] = w[i - 4 + 2];
        temp[3] = w[i - 4 + 3];

        if (i / 4 % Nk == 0) {
            RotWord(temp);
            SubWord(temp);
            Round(rcon, i / (Nk * 4));
            Xor(temp, rcon, temp);
        }
        else if (Nk > 6 && i / 4 % Nk == 4) {
            SubWord(temp);
        }

        w[i + 0] = w[i - 4 * Nk] ^ temp[0];
        w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
        w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
        w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
        i += 4;
    }
}

// performing the FFmul operation
unsigned char AEScipher::ffMultiply(unsigned char a, unsigned char b) {
    unsigned char bw[4];
    unsigned char res = 0;
    int i;

    bw[0] = b;
    for (i = 1; i < 4; ++i) {
        bw[i] = bw[i - 1] << 1;
        if (bw[i - 1] & 0x80) {
            bw[i] ^= 0x1b;
        }
    }

    for (i = 0; i < 4; ++i) {
        if ((a >> i) & 0x01) {
            res ^= bw[i];
        }
    }

    return res;
}

// replacing bytes in the status matrix
void AEScipher::subBytes(unsigned char state[4][Nb]) {
    unsigned char s;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < Nb; j++) {
            s = state[i][j];
            state[i][j] = sBox[s / 16][s % 16];
        }
    }
}

void AEScipher::InvsubBytes(unsigned char state[4][Nb])
{
    unsigned char s;
    InvSbox();
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < Nb; j++) {
            s = state[i][j];
            state[i][j] = invSbox[s / 16][s % 16];
        }
    }

}

// cyclic shift of rows in the state matrix
void AEScipher::shiftRows(unsigned char state[][4]) {
    unsigned char t[4];
    for (int r = 1; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            t[c] = state[r][(c + r) % 4];
        }
        for (int c = 0; c < 4; ++c) {
            state[r][c] = t[c];
        }
    }
}

// line shift
void AEScipher::ShiftRows(unsigned char state[4][Nb]) {

    ShiftRow(state, 1, 1);
    ShiftRow(state, 2, 2);
    ShiftRow(state, 3, 3);

}

void AEScipher::ShiftRow(unsigned char state[4][Nb], unsigned int i, unsigned int n)
{
    unsigned char tmp[Nb];
    for (unsigned int j = 0; j < Nb; j++) {
        tmp[j] = state[i][(j + n) % Nb];
    }
    memcpy(state[i], tmp, Nb * sizeof(unsigned char));

}

void AEScipher::InvShiftRows(unsigned char state[4][Nb])
{
    ShiftRow(state, 1, Nb - 1);
    ShiftRow(state, 2, Nb - 2);
    ShiftRow(state, 3, Nb - 3);
}

// shuffling columns in the state matrix
void AEScipher::mixColumns(unsigned char state[4][Nb]) {
    unsigned char t[4];
    int r, c;
    for (c = 0; c < 4; ++c) {
        for (r = 0; r < 4; ++r) {
            t[r] = state[r][c];
        }
        for (r = 0; r < 4; ++r) {
            state[r][c] = ffMultiply(0x02, t[r]) ^
                ffMultiply(0x03, t[(r + 1) % 4]) ^
                ffMultiply(0x01, t[(r + 2) % 4]) ^
                ffMultiply(0x01, t[(r + 3) % 4]);
        }
    }
}

// mixing columns
void AEScipher::InvMixColumns(unsigned char state[][4]) {
    unsigned char t[4];
    int r, c;
    for (c = 0; c < 4; ++c) {
        for (r = 0; r < 4; ++r) {
            t[r] = state[r][c];
        }
        for (r = 0; r < 4; ++r) {
            state[r][c] = ffMultiply(0x0E, t[r]) ^
                ffMultiply(0x0B, t[(r + 1) % 4]) ^
                ffMultiply(0x0D, t[(r + 2) % 4]) ^
                ffMultiply(0x09, t[(r + 3) % 4]);
        }
    }
}

// performing the XOR operation on the round state and key matrices
void AEScipher::addRoundKey(unsigned char state[4][Nb], unsigned char* key) {
    for (int c = 0; c < 4; ++c) {
        for (int r = 0; r < 4; ++r) {
            state[r][c] ^= key[c + 4 * r];
        }
    }
}

// data block encryption
void AEScipher::EncryptBlock(const unsigned char input[], unsigned char out[], unsigned char* roundKeys) {

    unsigned char state[4][Nb];

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < Nb; ++j) {
            state[i][j] = input[i + 4 * j];
        }
    }

    addRoundKey(state, roundKeys);

    int round;

    for (round = 1; round <= Nr - 1; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKeys + round * 4 * Nb);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKeys + Nr * 4 * Nb);

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            out[i + 4 * j] = state[i][j];
        }
    }

}

// inverted S-Box transformation  сheck
void invertSBox(const unsigned char* sBox, unsigned char* invSBox) {
    for (int i = 0; i < 256; ++i) {
        invSBox[sBox[i]] = static_cast<unsigned char>(i);
    }
}

void AEScipher::DecryptionBlock(const unsigned char input[], unsigned char output[],
    unsigned char* roundKeys) {
    unsigned char state[4][Nb];


    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < Nb; c++) {
            state[r][c] = input[c * 4 + r];
        }
    }

    addRoundKey(state, roundKeys + Nr * 4 * Nb);

    int round;

    for (round = Nr-1; round >= 1; round--) {
        InvsubBytes(state);
        InvShiftRows(state);
        addRoundKey(state, roundKeys + round * 4 * Nb);
        InvMixColumns(state);
    }

    InvsubBytes(state);
    InvShiftRows(state);
    addRoundKey(state, roundKeys + round * 4 * Nb);

    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < Nb; c++) {
            output[c * 4 + r] = state[r][c];
        }
    }
}


unsigned char* AEScipher::EncryptionAES(const unsigned char fileEn[], size_t fileLen,
    const unsigned char keyEn [])
{

    unsigned char* EncryptText = new unsigned char[fileLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];

    keyExpansion(keyEn, roundKeys);

    for (size_t i = 0; i < fileLen; i+= blockBytesLen) {
        EncryptBlock(fileEn + i, EncryptText + i, roundKeys); 
    }

    delete[] roundKeys;

    return EncryptText;
}

void AEScipher::StartEncryption()
{
    for (int i = 0; i < keyss.size(); i++) {

        unsigned char* EncrytData = EncryptionAES(files[i].data(), files[i].size(), keyss[i].data());
;
        std::vector<unsigned char > filesEncriptdata(EncrytData, EncrytData + files[i].size());


        filesEncript.push_back(filesEncriptdata);

        // write EncrytData in file 
        WriteDecryptEncriptData(0, filesEncriptdata, i);


        delete[] EncrytData;

    }
}




unsigned char* AEScipher::DecryptionAES(const unsigned char fileDe[], size_t fileLen,
    const unsigned char keyDe[])
{

    unsigned char* DecryptionText = new unsigned char[fileLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];

    keyExpansion(keyDe, roundKeys);

    for (size_t i = 0; i < fileLen; i += blockBytesLen) {
        DecryptionBlock(fileDe + i, DecryptionText + i, roundKeys); 
    }

    delete[] roundKeys;

    return DecryptionText;
}

void AEScipher::StartDecryption(bool index, int numberFile)
{
    for (int i = 0; i < keyss.size(); i++) {
        if (index == 0) 
            numberFile = i;

        unsigned char* DecryptionData = DecryptionAES(filesEncript[numberFile].data(), filesEncript[numberFile].size(), keyss[i].data());

        std::vector<unsigned char > filesDecryptdata(DecryptionData, DecryptionData + filesEncript[numberFile].size());
        filesDescript.push_back(filesDecryptdata);

        std::string strData(filesDecryptdata.begin(), filesDecryptdata.end());


        MD5 md5;

        std::string hash_check = md5(strData.c_str(), strData.length());

        if (hash_check == hash[numberFile]) {
            WriteDecryptEncriptData(1, filesDecryptdata, numberFile);
        }


        delete[] DecryptionData;
    }
}

void AEScipher::StartDecryptionShuffer()
{


    for (int i = 0; i < filesEncript.size(); i++) {

        StartDecryption(1, i);
           
    }
}

void AEScipher::WriteDecryptEncriptData(bool decrypt, std::vector<unsigned char > Data, int numberFile)
{
   

    std::string filename;

    if (decrypt == 1) {
        std::cout << "Decrypt file " << numberFile << std::endl;
        filename = "data/Decrypted/file" + std::to_string(numberFile) + ".bin";
    }
    else {
        std::cout << "Encript file " << numberFile << std::endl;
        filename = "data/Encrypted/file" + std::to_string(numberFile) + ".bin";
    }

    WriteFile(Data, filename);
    std::cout << "Data written to " << filename << std::endl << std::endl;

}


