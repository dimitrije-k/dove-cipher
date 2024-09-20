#ifndef DOVE_H_
#define DOVE_H_

#include <stddef.h>

void dove_init_keychain(const void* key, void* keychain, size_t rounds);
void dove_encrypt(const void* keychain, void* block, size_t rounds);
void dove_decrypt(const void* keychain, void* block, size_t rounds);

#endif
