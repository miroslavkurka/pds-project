#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "md5.h" 

int main() {
    const char *input_data = "123";
    size_t input_len = strlen(input_data);

    uint8_t digest[16];

    md5_hash((const uint8_t *)input_data, input_len, digest);

    printf("MD5 Hash: ");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    return 0;
}
