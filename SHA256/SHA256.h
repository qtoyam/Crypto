#ifndef __SHA256__
#define __SHA256__

#include "SHA256_Consts\SHA256_Basic.h"
#include "Types.h"
#include "DLL_Basic.h"

typedef struct
{
	u8 buffer[BLOCK_SIZE];
	u32 buffer_size;
	u64 total_size;
	u32 hash[8];
} sha256_ctx;

void SHARED_LIB SHA256_CreateHandle(sha256_ctx **ctx);
void SHARED_LIB SHA256_DestroyHandle(sha256_ctx *ctx);
void SHARED_LIB SHA256_Initialize(sha256_ctx *ctx);
void SHARED_LIB SHA256_Transform(sha256_ctx *ctx, const void *input, u64 size);
void SHARED_LIB SHA256_Finalize(sha256_ctx *ctx, void *output);
void SHARED_LIB SHA256_Clone(const sha256_ctx *__restrict source, sha256_ctx *__restrict destination);

void SHARED_LIB SHA256_GenerateHash(const void *input, void *output, u64 size);

#endif //__SHA256__