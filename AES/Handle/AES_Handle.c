#include "AES_Handle.h"

#include <malloc.h>

#include "Types.h"
#include "..\AES_Consts\Aes_Basic.h"

#include "Macro.h"

void SHARED_LIB AES_CreateHandle(void **handle)
{
	*handle = _aligned_malloc(AES_HANDLE_SIZE, AES_HANDLE_ALIGN);
}
void SHARED_LIB AES_SetIV(void *__restrict handle, const void *__restrict iv)
{
	handle = ASSUME_ALIGNED(handle, AES_HANDLE_ALIGN);
	u8 *handle8 = (u8 *)handle + AES_HANDLE_CTR_START;
	const u8 *iv8 = (const u8 *)iv;
	for (uiter i = 0; i < CTR_SIZE; i++)
	{
		handle8[i] = iv8[i];
	}
}
void SHARED_LIB AES_DestroyHandle(void *handle)
{
	handle = ASSUME_ALIGNED(handle, AES_HANDLE_ALIGN);
	CLEAR_MEMW(handle, AES_HANDLE_SIZEW);
	_aligned_free(handle);
}

void SHARED_LIB AES_Clone(const void *__restrict source, void *__restrict destination)
{
	for (uiter i = 0; i < AES_HANDLE_SIZEW; i++)
	{
		PUT32(destination, i, GET32(source, i));
	}
}