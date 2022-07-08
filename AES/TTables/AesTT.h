#ifndef __AesTT__
#define __AesTT__

#include "Dll_Basic.h"
#include "Types.h"

void SHARED_LIB AESTT_SetKey(void *handle, const void *key);

void SHARED_LIB AESTT_Encrypt(const void *__restrict handle, const void *in, void *out,
						u32 initialCounter, u64 size);

void SHARED_LIB AESTT_EncryptBlock(const void *__restrict handle, const void *in, void *out,
							 u32 initialCounter);

#endif //__AesTT__