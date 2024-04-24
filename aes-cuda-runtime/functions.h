#pragma once

#define BYTE unsigned char

#include "cuda_runtime.h"
#include "device_launch_parameters.h"

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

__device__ void AES_SubBytes(BYTE state[], BYTE sbox[]);
__device__ void AES_AddRoundKey(BYTE state[], BYTE rkey[]);
__device__ void AES_ShiftRows(BYTE state[], BYTE shifttab[]);
__device__ void AES_MixColumns(BYTE state[], BYTE AES_xtime[]);
__device__ void AES_MixColumns_Inv(BYTE state[], BYTE AES_xtime[]);
int AES_ExpandKey(BYTE key[], int keyLen, BYTE AES_Sbox[]);

__device__ void AES_Initialize_Encrypt(BYTE AES_Sbox_init[], BYTE AES_ShiftRowTab[], BYTE AES_xtime[]);
__device__ void AES_Initialize_Decrypt(BYTE AES_Sbox_Inv_init[], BYTE AES_ShiftRowTab_Inv[], BYTE AES_xtime[]);

__global__ void AES_Encrypt_base(AES_block aes_block_array[], BYTE key[], int keyLen, int block_number);
__global__ void AES_Decrypt_base(AES_block aes_block_array[], BYTE key[], int keyLen, int block_number);

void cudaEncrypt(AES_block*& aes_block_array, BYTE key[], int expandKeyLen, int block_number);
void cudaDecrypt(AES_block*& aes_block_array, BYTE key[], int expandKeyLen, int block_number);

void readBlocksFromFile(char* inputFile, AES_block*& aes_block_array, int& block_number, int& incomplete_block_number);
void writeBlocksToFile(char* inputFile, AES_block* aes_block_array, int block_number, int incomplete_block_number);
void getKey(char* keyLine, BYTE key[16 * (14 + 1)], int& expandKeyLen);

AES_block* AES_Encrypt(char* keyLine, AES_block* aes_block_array, int block_number, int incomplete_block_number);
AES_block* AES_Decrypt(char* keyLine, AES_block* aes_block_array, int block_number, int incomplete_block_number);

