#include "functions.h"

/* ----- HELPERS ----- */

void printBytes(BYTE s[], int len) {
    for (int i = 0; i < len; i++)
        printf("%02x ", s[i]);
    printf("\n");
}

void printChars(BYTE s[], int len) {
    for (int i = 0; i < len; i++)
        printf("%c", s[i]);
    printf("\n");
}

void printToFile(BYTE s[], int len, FILE* fp) {
    for (int i = 0; i < len; i++) {
        fprintf(fp, "%c", s[i]);
    }
}

void generateIV(BYTE iv[], int ivSize) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < ivSize; i++) {
        iv[i] = static_cast<BYTE>(dis(gen));
    }
}

BYTE AES_Sbox_init[] =
{
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* ----- AES FUNCTIONS ----- */

__device__ void AES_SubBytes(BYTE state[], BYTE sbox[]) {
    for (int i = 0; i < 16; i++)
        state[i] = sbox[state[i]];
}

__device__ void AES_AddRoundKey(BYTE state[], BYTE rkey[]) {
    for (int i = 0; i < 16; i++)
        state[i] ^= rkey[i];
}

__device__ void AES_ShiftRows(BYTE state[], BYTE shifttab[]) {
    BYTE temp[16];
    for (int i = 0; i < 16; i++)
        temp[i] = state[shifttab[i]];
    memcpy(state, temp, 16);
}

__device__ void AES_MixColumns(BYTE state[], BYTE AES_xtime[]) {
    for (int i = 0; i < 16; i += 4) {
        BYTE s0 = state[i + 0], s1 = state[i + 1];
        BYTE s2 = state[i + 2], s3 = state[i + 3];
        BYTE h = s0 ^ s1 ^ s2 ^ s3;
        state[i + 0] ^= h ^ AES_xtime[s0 ^ s1];
        state[i + 1] ^= h ^ AES_xtime[s1 ^ s2];
        state[i + 2] ^= h ^ AES_xtime[s2 ^ s3];
        state[i + 3] ^= h ^ AES_xtime[s3 ^ s0];
    }
}

__device__ void AES_MixColumns_Inv(BYTE state[], BYTE AES_xtime[]) {
    for (int i = 0; i < 16; i += 4) {
        BYTE s0 = state[i + 0], s1 = state[i + 1];
        BYTE s2 = state[i + 2], s3 = state[i + 3];
        BYTE h = s0 ^ s1 ^ s2 ^ s3;
        BYTE xh = AES_xtime[h];
        BYTE h1 = AES_xtime[AES_xtime[xh ^ s0 ^ s2]] ^ h;
        BYTE h2 = AES_xtime[AES_xtime[xh ^ s1 ^ s3]] ^ h;
        state[i + 0] ^= h1 ^ AES_xtime[s0 ^ s1];
        state[i + 1] ^= h2 ^ AES_xtime[s1 ^ s2];
        state[i + 2] ^= h1 ^ AES_xtime[s2 ^ s3];
        state[i + 3] ^= h2 ^ AES_xtime[s3 ^ s0];
    }
}

int AES_ExpandKey(BYTE key[], int keyLen, BYTE AES_Sbox[]) {
    int kl = keyLen, ks, Rcon = 1, i, j;
    BYTE* temp;

    switch (kl) {
    case 16: ks = 16 * (10 + 1); break;
    case 24: ks = 16 * (12 + 1); break;
    case 32: ks = 16 * (14 + 1); break;
    default:
        fprintf(stderr, "Error: Only 16, 24, or 32 key lengths are allowed.\n");
        return -1;
    }

    for (i = kl; i < ks; i += 4) {
        temp = &key[i - 4];
        if (i % kl == 0) {
            BYTE tmp = temp[0];
            temp[0] = AES_Sbox[temp[1]] ^ Rcon;
            temp[1] = AES_Sbox[temp[2]];
            temp[2] = AES_Sbox[temp[3]];
            temp[3] = AES_Sbox[tmp];
            if ((Rcon <<= 1) >= 256)
                Rcon ^= 0x11b;
        }
        else if ((kl > 24) && (i % kl == 16)) {
            for (j = 0; j < 4; j++)
                temp[j] = AES_Sbox[temp[j]];
        }
        for (j = 0; j < 4; j++)
            key[i + j] = key[i + j - kl] ^ temp[j];
    }
    return ks;
}

// AES_Encrypt & AES_Decrypt

__device__ void AES_Initialize_Encrypt(BYTE AES_Sbox_init[], BYTE AES_ShiftRowTab[], BYTE AES_xtime[]) {

    BYTE AES_Sbox[] =
    {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    };

    int i;

    for (i = 0; i < 256; ++i) {
        AES_Sbox_init[i] = AES_Sbox[i];
    }

    for (i = 0; i < 16; ++i) {
        AES_ShiftRowTab[i] = (i % 4) * 4 + (i / 4);
    }

    for (i = 0; i < 128; i++) {
        AES_xtime[i] = i << 1;
        AES_xtime[128 + i] = (i << 1) ^ 0x1b;
    }
}

__device__ void AES_Initialize_Decrypt(BYTE AES_Sbox_Inv_init[], BYTE AES_ShiftRowTab_Inv[], BYTE AES_xtime[]) {

    BYTE AES_Sbox_Inv[256] =
    {
        0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
        0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
        0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
        0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
        0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
        0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
        0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
        0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
        0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
        0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
        0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
        0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
        0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
        0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
        0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
        0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
    };

    int i;

    for (i = 0; i < 256; ++i) {
        AES_Sbox_Inv_init[i] = AES_Sbox_Inv[i];
    }

    for (i = 0; i < 16; i++) {
        AES_ShiftRowTab_Inv[(i % 4) * 4 + (i / 4)] = i;
    }
        
    for (i = 0; i < 128; i++) {
        AES_xtime[i] = i << 1;
        AES_xtime[128 + i] = (i << 1) ^ 0x1b;
    }
}

__global__ void AES_Encrypt_ECB(AES_block aes_block_array[], BYTE key[], int keyLen, int block_number) {

    int gt_index = blockDim.x * blockIdx.x + threadIdx.x;

    __shared__ BYTE AES_ShiftRowTab[16];
    __shared__ BYTE AES_xtime[256];
    __shared__ BYTE AES_Sbox_init[256];

    AES_Initialize_Encrypt(AES_Sbox_init, AES_ShiftRowTab, AES_xtime);

    if (gt_index < block_number) {

        BYTE block[16];

        for (int i = 0; i < 16; i++) {
            block[i] = aes_block_array[gt_index].block[i];
        }

        __syncthreads();

        int l = keyLen, i;

        AES_AddRoundKey(block, &key[0]);
        for (i = 16; i < l - 16; i += 16) {
            AES_SubBytes(block, AES_Sbox_init);
            AES_ShiftRows(block, AES_ShiftRowTab);
            AES_MixColumns(block, AES_xtime);
            AES_AddRoundKey(block, &key[i]);
        }
        AES_SubBytes(block, AES_Sbox_init);
        AES_ShiftRows(block, AES_ShiftRowTab);
        AES_AddRoundKey(block, &key[i]);

        for (int i = 0; i < 16; i++) {
            aes_block_array[gt_index].block[i] = block[i];
        }

    }

}

__global__ void AES_Decrypt_ECB(AES_block aes_block_array[], BYTE key[], int keyLen, int block_number) {

    int gt_index = blockDim.x * blockIdx.x + threadIdx.x;

    __shared__ BYTE AES_ShiftRowTab_Inv[16];
    __shared__ BYTE AES_xtime[256];
    __shared__ BYTE AES_Sbox_Inv_init[256];

    AES_Initialize_Decrypt(AES_Sbox_Inv_init, AES_ShiftRowTab_Inv, AES_xtime);

    if (gt_index < block_number) {

        BYTE block[16];
        for (int i = 0; i < 16; i++) {
            block[i] = aes_block_array[gt_index].block[i];
        }

        __syncthreads();

        int l = keyLen, i;
        AES_AddRoundKey(block, &key[l - 16]);
        AES_ShiftRows(block, AES_ShiftRowTab_Inv);
        AES_SubBytes(block, AES_Sbox_Inv_init);
        for (i = l - 32; i >= 16; i -= 16) {
            AES_AddRoundKey(block, &key[i]);
            AES_MixColumns_Inv(block, AES_xtime);
            AES_ShiftRows(block, AES_ShiftRowTab_Inv);
            AES_SubBytes(block, AES_Sbox_Inv_init);
        }
        AES_AddRoundKey(block, &key[0]);

        for (int i = 0; i < 16; i++) {
            aes_block_array[gt_index].block[i] = block[i];
        }

    }
}

__global__ void AES_Encrypt_CBC(AES_block aes_block_array[], BYTE key[], int keyLen, BYTE iv[], int block_number) {
    int gt_index = blockDim.x * blockIdx.x + threadIdx.x;

    __shared__ BYTE AES_ShiftRowTab[16];
    __shared__ BYTE AES_xtime[256];
    __shared__ BYTE AES_Sbox_init[256];

    AES_Initialize_Encrypt(AES_Sbox_init, AES_ShiftRowTab, AES_xtime);

    if (gt_index < block_number) {
        BYTE block[16];
        BYTE prev_block[16];

        for (int i = 0; i < 16; i++) {
            block[i] = aes_block_array[gt_index].block[i];
            prev_block[i] = (gt_index == 0) ? iv[i] : aes_block_array[gt_index - 1].block[i];
        }

        __syncthreads();

        for (int i = 0; i < 16; i++) {
            block[i] ^= prev_block[i];
        }

        int l = keyLen, i;

        AES_AddRoundKey(block, &key[0]);
        for (i = 16; i < l - 16; i += 16) {
            AES_SubBytes(block, AES_Sbox_init);
            AES_ShiftRows(block, AES_ShiftRowTab);
            AES_MixColumns(block, AES_xtime);
            AES_AddRoundKey(block, &key[i]);
        }
        AES_SubBytes(block, AES_Sbox_init);
        AES_ShiftRows(block, AES_ShiftRowTab);
        AES_AddRoundKey(block, &key[i]);

        for (int i = 0; i < 16; i++) {
            aes_block_array[gt_index].block[i] = block[i];
        }
    }
}

__global__ void AES_Decrypt_CBC(AES_block aes_block_array[], BYTE key[], int keyLen, BYTE iv[], int block_number) {
    int gt_index = blockDim.x * blockIdx.x + threadIdx.x;

    __shared__ BYTE AES_ShiftRowTab_Inv[16];
    __shared__ BYTE AES_xtime[256];
    __shared__ BYTE AES_Sbox_Inv_init[256];

    AES_Initialize_Decrypt(AES_Sbox_Inv_init, AES_ShiftRowTab_Inv, AES_xtime);

    if (gt_index < block_number) {
        BYTE block[16];
        BYTE prev_block[16];

        for (int i = 0; i < 16; i++) {
            block[i] = aes_block_array[gt_index].block[i];
            prev_block[i] = (gt_index == 0) ? iv[i] : aes_block_array[gt_index - 1].block[i];
        }

        __syncthreads();

        int l = keyLen, i;
        AES_AddRoundKey(block, &key[l - 16]);
        AES_ShiftRows(block, AES_ShiftRowTab_Inv);
        AES_SubBytes(block, AES_Sbox_Inv_init);
        for (i = l - 32; i >= 16; i -= 16) {
            AES_AddRoundKey(block, &key[i]);
            AES_MixColumns_Inv(block, AES_xtime);
            AES_ShiftRows(block, AES_ShiftRowTab_Inv);
            AES_SubBytes(block, AES_Sbox_Inv_init);
        }
        AES_AddRoundKey(block, &key[0]);


        for (int i = 0; i < 16; i++) {
            block[i] ^= prev_block[i];
            aes_block_array[gt_index].block[i] = block[i];
        }
    }
}

void readBlocksFromFile(char* inputFile, AES_block*& aes_block_array, int& block_number, int& incomplete_block_number) {

    std::ifstream ifs;
    ifs.open(inputFile, std::ios::binary);

    if (!ifs) {
        std::cerr << "Cannot open the input file" << std::endl;
        exit(1);
    }

    ifs.seekg(0, std::ios::end);
    int fileLength = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    block_number = fileLength / 16;
    incomplete_block_number = fileLength % 16;

    if (incomplete_block_number != 0)
        aes_block_array = new AES_block[block_number + 1];
    else
        aes_block_array = new AES_block[block_number];
    char temp[16];

    // read blocks
    for (int i = 0; i < block_number; i++) {
        ifs.read(temp, 16);
        for (int j = 0; j < 16; j++) {
            aes_block_array[i].block[j] = (unsigned char)temp[j];
        }
    }

    // read incomplete blocks
    if (incomplete_block_number != 0) {
        ifs.read(temp, incomplete_block_number);
        for (int j = 0; j < 16; j++) {
            aes_block_array[block_number].block[j] = (unsigned char)temp[j];
        }
        for (int j = 1; j <= 16 - incomplete_block_number; j++)
            aes_block_array[block_number].block[16 - j] = 0x00;
        block_number++;
    }

    ifs.close();
}

void writeBlocksToFile(char* inputFile, AES_block* aes_block_array, int block_number, int incomplete_block_number) {

    FILE* file;
    file = fopen(inputFile, "wb");

    for (int i = 0; i < block_number ; i++) {
        printToFile(aes_block_array[i].block, 16, file);
    }

    fclose(file);

}

void cudaEncrypt(AES_block*& aes_block_array, BYTE key[], int expandKeyLen, BYTE iv[], int block_number) {

    cudaSetDevice(0);
    cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, 0);

    int nnm = prop.multiProcessorCount;
    AES_block* cuda_aes_block_array;
    BYTE* cuda_key;
    int thrdperblock = block_number / nnm;

    // cuda threads
    if (block_number % nnm > 0)
        thrdperblock++;
    if (thrdperblock > 1024) {
        thrdperblock = 1024;
        nnm = block_number / 1024;
        if (block_number % 1024 > 0) {
            nnm++;
        }
    }
    dim3 ThreadperBlock(thrdperblock);
    dim3 BlockperGrid(nnm);

    cudaMalloc(&cuda_aes_block_array, block_number * sizeof(class AES_block));
    cudaMalloc(&cuda_key, 16 * 15 * sizeof(BYTE));
    cudaMemcpy(cuda_aes_block_array, aes_block_array, block_number * sizeof(class AES_block), cudaMemcpyHostToDevice);
    cudaMemcpy(cuda_key, key, 16 * 15 * sizeof(BYTE), cudaMemcpyHostToDevice);

    AES_Encrypt_ECB << < BlockperGrid, ThreadperBlock >> > (cuda_aes_block_array, cuda_key, expandKeyLen, block_number);
    //AES_Encrypt_CBC << <BlockperGrid, ThreadperBlock >> > (cuda_aes_block_array, cuda_key, expandKeyLen, iv, block_number);
    cudaMemcpy(aes_block_array, cuda_aes_block_array, block_number * sizeof(class AES_block), cudaMemcpyDeviceToHost);

    cudaFree(cuda_aes_block_array);
    cudaFree(cuda_key);
}

void cudaDecrypt(AES_block*& aes_block_array, BYTE key[], int expandKeyLen, BYTE iv[], int block_number) {
    
    cudaSetDevice(0);
    cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, 0);

    int nnm = prop.multiProcessorCount;
    AES_block* cuda_aes_block_array;
    BYTE* cuda_key;
    int thrdperblock = block_number / nnm;

    // cuda threads
    if (block_number % nnm > 0)
        thrdperblock++;
    if (thrdperblock > 1024) {
        thrdperblock = 1024;
        nnm = block_number / 1024;
        if (block_number % 1024 > 0) {
            nnm++;
        }
    }
    dim3 ThreadperBlock(thrdperblock);
    dim3 BlockperGrid(nnm);

    cudaMalloc(&cuda_aes_block_array, block_number * sizeof(class AES_block));
    cudaMalloc(&cuda_key, 16 * 15 * sizeof(BYTE));
    cudaMemcpy(cuda_aes_block_array, aes_block_array, block_number * sizeof(class AES_block), cudaMemcpyHostToDevice);
    cudaMemcpy(cuda_key, key, 16 * 15 * sizeof(BYTE), cudaMemcpyHostToDevice);

    AES_Decrypt_ECB << < BlockperGrid, ThreadperBlock >> > (cuda_aes_block_array, cuda_key, expandKeyLen, block_number);
    //AES_Decrypt_CBC << <BlockperGrid, ThreadperBlock >> > (cuda_aes_block_array, cuda_key, expandKeyLen, iv, block_number);
    cudaMemcpy(aes_block_array, cuda_aes_block_array, block_number * sizeof(class AES_block), cudaMemcpyDeviceToHost);

    cudaFree(cuda_aes_block_array);
    cudaFree(cuda_key);
}

void getKey(char* keyLine, BYTE key[16 * (14 + 1)], int& expandKeyLen) {
   
    /* ----- KEY ----- */

    int keyLen = 0;
    for (int i = 0; keyLine[i] != '\0'; ++i) {
        key[keyLen++] = keyLine[i];
    }
    expandKeyLen = AES_ExpandKey(key, keyLen, AES_Sbox_init);

}

AES_block * AES_Encrypt(char* keyLine, AES_block* aes_block_array, int block_number, BYTE iv[], int incomplete_block_number) {

    /* ----- ENCRYPTION ----- */

    BYTE key[16 * (14 + 1)];
    int expandKeyLen = 0;

    getKey(keyLine, key, expandKeyLen);

    generateIV(iv, sizeof(iv));

    //AES_Encrypt_ECB(aes_block_array, key, expandKeyLen, block_number);
    //AES_Encrypt_CBC(aes_block_array, key, expandKeyLen, iv, block_number);
    cudaEncrypt(aes_block_array, key, expandKeyLen, iv, block_number);

    return aes_block_array;
}

AES_block * AES_Decrypt(char* keyLine, AES_block* aes_block_array, int block_number, BYTE iv[], int incomplete_block_number) {

    /* ----- DECRYPTION ----- */

    BYTE key[16 * (14 + 1)];
    int expandKeyLen = 0;

    getKey(keyLine, key, expandKeyLen);

    //AES_Decrypt_ECB(aes_block_array, key, expandKeyLen, block_number);
    //AES_Decrypt_CBC(aes_block_array, key, expandKeyLen, iv, block_number);
    cudaDecrypt(aes_block_array, key, expandKeyLen, iv, block_number);

    return aes_block_array;
}