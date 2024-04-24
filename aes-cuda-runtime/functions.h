#pragma once

#define BYTE unsigned char

#include <iostream>
#include <fstream>
#include <cstring>

class AES_block {
public:
    BYTE block[16];
};

void printBytes(BYTE s[], int len);
void printChars(BYTE s[], int len);
void printToFile(BYTE b[], int len, FILE* fp);

void AES_SubBytes(BYTE state[], BYTE sbox[]);
void AES_AddRoundKey(BYTE state[], BYTE rkey[]);
void AES_ShiftRows(BYTE state[], BYTE shifttab[]);
void AES_MixColumns(BYTE state[], BYTE AES_xtime[]);
void AES_MixColumns_Inv(BYTE state[], BYTE AES_xtime[]);
int AES_ExpandKey(BYTE key[], int keyLen, BYTE AES_Sbox[]);

void AES_Initialize_Encrypt(BYTE AES_ShiftRowTab[], BYTE AES_xtime[]);
void AES_Initialize_Decrypt(BYTE AES_ShiftRowTab_Inv[], BYTE AES_xtime[]);

void AES_Encrypt_base(AES_block aes_block_array[], BYTE key[], int keyLen, int block_number);
void AES_Decrypt_base(AES_block aes_block_array[], BYTE key[], int keyLen, int block_number);

void readBlocksFromFile(char* inputFile, AES_block*& aes_block_array, int& block_number, int& incomplete_block_number);
void writeBlocksToFile(char* inputFile, AES_block* aes_block_array, int block_number, int incomplete_block_number);
void getKey(char* keyLine, BYTE key[16 * (14 + 1)], int& expandKeyLen);

AES_block* AES_Encrypt(char* keyLine, AES_block* aes_block_array, int block_number, int incomplete_block_number);
AES_block* AES_Decrypt(char* keyLine, AES_block* aes_block_array, int block_number, int incomplete_block_number);
