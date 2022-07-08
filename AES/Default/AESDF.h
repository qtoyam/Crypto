#ifndef __AESDF__
#define __AESDF__

#include "DLL_Basic.h"
#include "Types.h"

void SHARED_LIB AESDF_SetKey(void *handle, const void *key);

void SHARED_LIB AESDF_Encrypt(const void *__restrict handle, const void *in, void *out,
							  u32 initialCounter, u64 size);

void SHARED_LIB AESDF_EncryptBlock(const void *__restrict handle, const void *in, void *out,
								   u32 initialCounter);

#endif //__AESDF__