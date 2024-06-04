#ifndef SHA2_H
#define SHA2_H

#include <inttypes.h>

#define SHA256_DIGEST_SIZE ( 256 / 8)
#define SHA256_BLOCK_SIZE  ( 512 / 8)

#define SHFR(x, n)    (x >> n)
#define ROTR_SHA(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define CH(x, y, z)  ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define SHA256_F1(x) (ROTR_SHA(x,  2) ^ ROTR_SHA(x, 13) ^ ROTR_SHA(x, 22))
#define SHA256_F2(x) (ROTR_SHA(x,  6) ^ ROTR_SHA(x, 11) ^ ROTR_SHA(x, 25))
#define SHA256_F3(x) (ROTR_SHA(x,  7) ^ ROTR_SHA(x, 18) ^ SHFR(x,  3))
#define SHA256_F4(x) (ROTR_SHA(x, 17) ^ ROTR_SHA(x, 19) ^ SHFR(x, 10))

typedef struct {
    unsigned int tot_len;
    unsigned int len;
    unsigned char block[2 * SHA256_BLOCK_SIZE];
    uint32_t h[8];
} sha256_ctx;


void sha256_init(sha256_ctx * ctx);
void sha256_update(sha256_ctx *ctx, const unsigned char *message,
                   unsigned int len);
void sha256_final(sha256_ctx *ctx, unsigned char *digest);


void sha256(const unsigned char *message, unsigned int len,
            unsigned char *digest);

void sha256d(const unsigned char *message, unsigned int len, unsigned char *digest);

#endif /* !SHA2_H */