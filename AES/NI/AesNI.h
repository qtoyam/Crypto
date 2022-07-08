#ifndef __AesNI__
#define __AesNI__

#include "Dll_Basic.h"
#include "Types.h"

#pragma GCC target("aes")

void SHARED_LIB AESNI_SetKey(void *handle, const void *key);

void SHARED_LIB AESNI_Encrypt(const void *__restrict handle, const void *in, void *out,
						u32 initialCounter, u64 size);

void SHARED_LIB AESNI_EncryptBlock(const void *__restrict handle, const void *in, void *out,
							 u32 initialCounter);

#endif //__AesNI__