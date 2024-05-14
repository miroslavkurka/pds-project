#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "md5.h" 

// Define the alphabet for brute-force cracking
char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

__global__ void md5_crack(const uint8_t *target_hash, char *alphabet, int alphabet_len, int len) {
    
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    char password[6]; // Password length (max 5 characters)
    int temp = idx;
    for (int i = 0; i < len; ++i) {
        password[i] = alphabet[temp % alphabet_len];
        temp /= alphabet_len;
    }
    password[len] = '\0';

    if (idx < alphabet_len) {
        // Hash the password candidate
        uint8_t digest[16];
        md5_hash((const uint8_t *)password, len, digest);

        // Compare the hash with the target hash
        if (cudaMemcpy(digest, target_hash, 16, cudaMemcpyDefault) == cudaSuccess) {
            printf("Password found: %s\n", password);
        }
    }
}

int main() {
    uint8_t target_hash[16]; // MD5 hash is 16 bytes (128 bits)

    md5_hash((const uint8_t *)"123", strlen("123"), target_hash);

    int threadsPerBlock = 256;
    int blocksPerGrid = 1; // We'll use just one block since we're iterating over the alphabet on the GPU
    int alphabet_len = strlen(alphabet);

    for (int len = 1; len <= 5; ++len) {
        md5_crack<<<blocksPerGrid, threadsPerBlock>>>(target_hash, alphabet, alphabet_len, len);

        cudaDeviceSynchronize();

        cudaError_t error = cudaGetLastError();
        if (error != cudaSuccess) {
            fprintf(stderr, "CUDA error: %s\n", cudaGetErrorString(error));
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}
