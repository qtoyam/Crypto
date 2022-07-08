#include "SHA256.h"

#include <malloc.h>

#include "Types.h"
#include "Macro.h"

#define ROTR32(v, r) (((v) >> (r)) | ((v) << (32 - (r))))
#define SHIFTR32(v, r) (v >> r)
#define S0(v) ((ROTR32(v, 7)) ^ (ROTR32(v, 18)) ^ (SHIFTR32(v, 3)))
#define S1(v) ((ROTR32(v, 17)) ^ (ROTR32(v, 19)) ^ (SHIFTR32(v, 10)))

#define SIG1(e) (ROTR32((e), 6) ^ ROTR32((e), 11) ^ ROTR32((e), 25))
#define CH(e, f, g) (((e) & (f)) ^ ((~(e)) & (g)))
#define T1(h, e, f, g, k, w) ((h) + (SIG1(e)) + (CH((e), (f), (g))) + (k) + (w))
#define SIG0(a) ((ROTR32((a), 2)) ^ (ROTR32((a), 13)) ^ (ROTR32((a), 22)))
#define MAJ(a, b, c) (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))
#define T2(a, b, c) ((SIG0((a))) + (MAJ((a), (b), (c))))

inline static void InitHashStateCore(u32 hash_state[HASH_SIZEW])
{
	hash_state[0] = h0;
	hash_state[1] = h1;
	hash_state[2] = h2;
	hash_state[3] = h3;
	hash_state[4] = h4;
	hash_state[5] = h5;
	hash_state[6] = h6;
	hash_state[7] = h7;
}

inline static void CopyFinalHashCore(u32 hash_state[HASH_SIZEW], void *output)
{
	for (uiter i = 0; i < HASH_SIZEW; i++)
	{
		PUT32(output, i, BSWAP32(hash_state[i]));
	}
}

inline static void TransformCore(u32 hash_state[HASH_SIZEW], u32 w[W_SIZEW])
{
	// vars
	u32 a, b, c, d, e, f, g, h, t1, t2;
	uiter i;

	// extend
	for (i = BLOCK_SIZEW; i < W_SIZEW; i++)
	{
		w[i] = w[i - 16] + S0(w[i - 15]) + w[i - 7] + S1(w[i - 2]);
	}

	// Initialize working variables to current hash value
	a = hash_state[0];
	b = hash_state[1];
	c = hash_state[2];
	d = hash_state[3];
	e = hash_state[4];
	f = hash_state[5];
	g = hash_state[6];
	h = hash_state[7];

	// Compression function main loop
	for (i = 0; i < W_SIZEW; i++)
	{
		t1 = T1(h, e, f, g, k[i], w[i]);
		t2 = T2(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	// Add the compressed chunk to the current hash value
	hash_state[0] += a;
	hash_state[1] += b;
	hash_state[2] += c;
	hash_state[3] += d;
	hash_state[4] += e;
	hash_state[5] += f;
	hash_state[6] += g;
	hash_state[7] += h;
}

// total_bit_length already includes last (passed) data size
inline static void FinalizeCore(u32 hash_state[HASH_SIZEW], const void *data, u32 data_size, u64 total_bit_length, u32 w[W_SIZEW])
{
	// tmp
	u32 tmp;
	uiter i;

	// copy full words
	tmp = data_size >> 2; // / WORD_SIZE
	for (i = 0; i < tmp; i++)
	{
		w[i] = BSWAP32(GET32(data, i));
	}

	// pad
	tmp = data_size & 3; // data_size % 4
	if (tmp == 0)		 // no extra bytes, just put padding
	{
		w[i] = 0x80000000U;
	}
	else if (tmp == 1)
	{
		w[i] =
			(GET8(data, i * WORD_SIZE + 0) << 24) | 0x00800000U;
	}
	else if (tmp == 2)
	{
		w[i] =
			(GET8(data, i * WORD_SIZE + 0) << 24) |
			(GET8(data, i * WORD_SIZE + 1) << 16) | 0x00008000U;
	}
	else // if (tmp == 3)
	{
		w[i] =
			(GET8(data, i * WORD_SIZE + 0) << 24) |
			(GET8(data, i * WORD_SIZE + 1) << 16) |
			(GET8(data, i * WORD_SIZE + 2) << 8) | 0x00000080U;
	}
	++i;

	// not enough space to append length,
	// need to pad, transform this block and prepare empty block
	if (i > (BLOCK_SIZEW - LENGTH_PADDING_SIZEW))
	{
		for (; i < BLOCK_SIZEW; i++)
		{
			w[i] = 0x00000000U;
		}
		TransformCore(hash_state, w); // transform block
		i = 0;						  // fill FULL last block with zeroes
	}
	for (; i < (BLOCK_SIZEW - LENGTH_PADDING_SIZEW); i++)
	{
		w[i] = 0x00000000U;
	}

	// append length
	w[BLOCK_SIZEW - LENGTH_PADDING_SIZEW + 0] = total_bit_length >> 32;
	w[BLOCK_SIZEW - LENGTH_PADDING_SIZEW + 1] = total_bit_length >> 0;

	// transform final block
	TransformCore(hash_state, w);
}

void SHARED_LIB SHA256_CreateHandle(sha256_ctx **ctx)
{
	*ctx = (sha256_ctx *)malloc(sizeof(sha256_ctx));
}
void SHARED_LIB SHA256_DestroyHandle(sha256_ctx *ctx)
{
	CLEAR_MEMW(ctx, sizeof(sha256_ctx) / WORD_SIZE);
	free(ctx);
}
void SHARED_LIB SHA256_Initialize(sha256_ctx *ctx)
{
	InitHashStateCore(ctx->hash);
	ctx->buffer_size = 0;
	ctx->total_size = 0;
}
void SHARED_LIB SHA256_Transform(sha256_ctx *ctx, const void *input, u64 size)
{
	// vars
	u32 w[W_SIZEW];
	uiter i;
	u64 block_i, block_nb, extraBytes;
	const u32 *inpw;

	// process full blocks
	if (ctx->buffer_size != 0) // buffer not empty
	{
		if (size < (BLOCK_SIZE - ctx->buffer_size)) // not enough bytes to get full block
		{
			// just copy input to buffer
			for (i = 0; i < size; i++)
			{
				ctx->buffer[ctx->buffer_size + i] = GET8(input, i);
			}
			ctx->total_size += size;
			ctx->buffer_size += size;
			return;
		}
		// we have enough bytes to get full block
		// copy from buffer
		for (i = 0; i < ctx->buffer_size; i++)
		{
			PUT8(w, i, ctx->buffer[i]);
		}
		// now we can easily compute next vars cauze (BLOCK_SIZE - i) is size taken from input to complete block
		block_nb = (size - (BLOCK_SIZE - i)) >> 6;
		extraBytes = (size - (BLOCK_SIZE - i)) & (BLOCK_SIZE - 1);
		inpw = (const u32*)(((const u8 *)input) + (BLOCK_SIZE - i));
		// copy from actual input
		for (; i < BLOCK_SIZE; i++)
		{
			PUT8(w, i, GET8(input, i - ctx->buffer_size));
		}
		// bswap copied data
		for (i = 0; i < BLOCK_SIZEW; i++)
		{
			w[i] = BSWAP32(w[i]);
		}
		TransformCore(ctx->hash, w);
		// ctx->buffer_size and total_size will be set later
	}
	else
	{
		inpw = (const u32 *)input;
		block_nb = size >> 6;
		extraBytes = size & (BLOCK_SIZE - 1);
	}
	for (block_i = 0; block_i < block_nb; block_i++)
	{
		// copy block
		for (i = 0; i < BLOCK_SIZEW; i++)
		{
			w[i] = BSWAP32(inpw[i]);
		}
		TransformCore(ctx->hash, w);
		inpw += BLOCK_SIZEW;
	}
	// not transformed bytes
	for (i = 0; i < extraBytes; i++) // loop starts always from zero becauze if we have already data in buffer -> we transform it
	{
		ctx->buffer[i] = GET8(inpw, i);
	}
	ctx->buffer_size = extraBytes;
	ctx->total_size += size;
}
void SHARED_LIB SHA256_Finalize(sha256_ctx *ctx, void *output)
{
	u32 w[W_SIZEW];
	FinalizeCore(ctx->hash, ctx->buffer, ctx->buffer_size, ctx->total_size << 3, w);
	CopyFinalHashCore(ctx->hash, output);
}
void SHARED_LIB SHA256_GenerateHash(const void *input, void *output, u64 size)
{
	// vars
	u32 hash_state[HASH_SIZEW], w[W_SIZEW];
	u32 i;
	u64 block_i, block_nb;
	// converts
	const u32 *inpw = (const u32 *)input;

	InitHashStateCore(hash_state);

	// process full blocks
	block_nb = size >> 6;
	for (block_i = 0; block_i < block_nb; block_i++)
	{
		// copy block
		for (i = 0; i < BLOCK_SIZEW; i++)
		{
			w[i] = BSWAP32(inpw[i]);
		}
		TransformCore(hash_state, w);
		inpw += BLOCK_SIZEW;
	}

	// process final block
	FinalizeCore(hash_state, inpw, size & (BLOCK_SIZE - 1), size * 8, w);

	// copy hash
	CopyFinalHashCore(hash_state, output);
}
