#include <openssl/evp.h>
int enc(EVP_CIPHER_CTX *ctx, unsigned char *key, unsigned char *iv) {
    return EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv);
}
