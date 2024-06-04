/************************************************************************************
*   written by: Bitmaker
*   based on: Blockstream Jade shaLib
*   thanks to @LarryBitcoin

*   Description:

*   NerdSha256plus is a custom C implementation of sha256d based on Blockstream Jade 
    code https://github.com/Blockstream/Jade

    The folowing file can be used on any ESP32 implementation using both cores

*************************************************************************************/
#ifndef nerdSHA256plus_H_
#define nerdSHA256plus_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


struct nerdSHA256_context {
    // uint8_t buffer[64];
    uint32_t digest[8];
    uint32_t digest_optimize[8];

    uint32_t temp1_Round4;
    uint32_t temp1_plus_temp2_Round4;

    uint32_t W1[3];

    uint32_t W16;
    uint32_t W17;
    uint32_t W18_without_S0_nonce;
    uint32_t W19_without_nonce;
};

/* Calculate midstate */
void nerd_mids(nerdSHA256_context* midstate, uint8_t* dataIn);

bool nerd_sha256d(nerdSHA256_context* midstate, uint8_t* dataIn, double pooldifficulty, uint8_t* doubleHash) __attribute__((hot));
// bool nerd_sha256d_new(nerdSHA256_context* midstate, uint8_t* dataIn, double pooldifficulty, uint8_t* doubleHash);

void ByteReverseWords(uint32_t* out, uint32_t* in, uint32_t byteCount);

#endif /* nerdSHA256plus_H_ */