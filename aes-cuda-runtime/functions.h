#pragma once

#define BYTE unsigned char

#include <iostream>

class AES_block {
public:
    BYTE block[16];
};

void printBytes(BYTE s[], int len);
void printChars(BYTE s[], int len);

void AES_SubBytes(BYTE state[], BYTE sbox[]);
void AES_AddRoundKey(BYTE state[], BYTE rkey[]);
void AES_ShiftRows(BYTE state[], BYTE shifttab[]);
void AES_MixColumns(BYTE state[], BYTE AES_xtime[]);
void AES_MixColumns_Inv(BYTE state[], BYTE AES_xtime[]);
int AES_ExpandKey(BYTE key[], int keyLen, BYTE AES_Sbox[]);

void AES_Initialize_Encrypt(BYTE AES_ShiftRowTab[], BYTE AES_xtime[]);
void AES_Initialize_Decrypt(BYTE AES_ShiftRowTab_Inv[], BYTE AES_xtime[]);

void AES_Encrypt(AES_block aes_block_array[], BYTE key[], int keyLen, int block_number);
void AES_Decrypt(AES_block aes_block_array[], BYTE key[], int keyLen, int block_number);

int dev();