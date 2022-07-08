#include "AesNI.h"

#include <wmmintrin.h>
#include <tmmintrin.h>

#include "..\AES_Consts\Aes_Basic.h"

#include "Types.h"
#include "Macro.h"

#define GenKey0(prevprev, prev, store, rcon)                   \
	store = _mm_aeskeygenassist_si128(prev, rcon);             \
	store = _mm_shuffle_epi32(store, _MM_SHUFFLE(3, 3, 3, 3)); \
	store = _mm_xor_si128(store, prevprev);                    \
	prevprev = _mm_slli_si128(prevprev, 4);                    \
	store = _mm_xor_si128(store, prevprev);                    \
	prevprev = _mm_slli_si128(prevprev, 4);                    \
	store = _mm_xor_si128(store, prevprev);                    \
	prevprev = _mm_slli_si128(prevprev, 4);                    \
	store = _mm_xor_si128(store, prevprev)

#define GenKey1(prevprev, prev, store)                         \
	store = _mm_aeskeygenassist_si128(prev, 0x00);             \
	store = _mm_shuffle_epi32(store, _MM_SHUFFLE(2, 2, 2, 2)); \
	store = _mm_xor_si128(store, prevprev);                    \
	prevprev = _mm_slli_si128(prevprev, 4);                    \
	store = _mm_xor_si128(store, prevprev);                    \
	prevprev = _mm_slli_si128(prevprev, 4);                    \
	store = _mm_xor_si128(store, prevprev);                    \
	prevprev = _mm_slli_si128(prevprev, 4);                    \
	store = _mm_xor_si128(store, prevprev)

void SHARED_LIB AESNI_SetKey(void *__restrict handle, const void *__restrict key)
{
	handle = ASSUME_ALIGNED(handle, AES_HANDLE_ALIGN);
	__m128i *ek = (__m128i *)handle + AES_HANDLE_EKEY_STARTV128;
	__m128i t1, t2, t3;
	t1 = _mm_loadu_si128((const __m128i_u *)key);
	t2 = _mm_loadu_si128((const __m128i_u *)key + 1);
	ek[0] = t1;
	ek[1] = t2;

	GenKey0(t1, t2, t3, 0x01);
	ek[2] = t3;
	GenKey1(t2, t3, t1);
	ek[3] = t1;
	GenKey0(t3, t1, t2, 0x02);
	ek[4] = t2;
	GenKey1(t1, t2, t3);
	ek[5] = t3;
	GenKey0(t2, t3, t1, 0x04);
	ek[6] = t1;
	GenKey1(t3, t1, t2);
	ek[7] = t2;
	GenKey0(t1, t2, t3, 0x08);
	ek[8] = t3;
	GenKey1(t2, t3, t1);
	ek[9] = t1;
	GenKey0(t3, t1, t2, 0x10);
	ek[10] = t2;
	GenKey1(t1, t2, t3);
	ek[11] = t3;
	GenKey0(t2, t3, t1, 0x20);
	ek[12] = t1;
	GenKey1(t3, t1, t2);
	ek[13] = t2;
	GenKey0(t1, t2, t3, 0x40);
	ek[14] = t3;
}

#ifdef __Aes__Increment_Counter_BE
#define SWAPMASK_VEC128_LOW32 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 14, 13, 12
#endif //__Aes__Increment_Counter_BE

#define AS__m128iu(pointer) ((__m128i_u *)(pointer))
#define ASC__m128iu(pointer) ((const __m128i_u *)(pointer))
#define RK(i) ((ASC__m128iu(handle) + AES_HANDLE_EKEY_STARTV128)[i])

void SHARED_LIB AESNI_EncryptBlock(const void *__restrict handle, const void *in, void *out, u32 initialCounter)
{
	// pre-func
	handle = ASSUME_ALIGNED(handle, AES_HANDLE_ALIGN);

	// vars
	__m128i ctr, in_vec;

	// * load iv
	ctr = _mm_load_si128(ASC__m128iu(handle) + AES_HANDLE_CTR_STARTV128);

	// * add initial counter
#ifdef __Aes__Increment_Counter_BE
	const __m128i swapmask = _mm_setr_epi8(SWAPMASK_VEC128_LOW32);
	ctr = _mm_shuffle_epi8(ctr, swapmask);
#endif //__Aes__Increment_Counter_BE
	ctr = _mm_add_epi32(ctr, _mm_set_epi32(initialCounter, 0, 0, 0));
#ifdef __Aes__Increment_Counter_BE
	ctr = _mm_shuffle_epi8(ctr, swapmask);
#endif //__Aes__Increment_Counter_BE

	// * encrypt block (ctr)
	ctr = _mm_xor_si128(ctr, RK(0));
	ctr = _mm_aesenc_si128(ctr, RK(1));
	ctr = _mm_aesenc_si128(ctr, RK(2));
	ctr = _mm_aesenc_si128(ctr, RK(3));
	ctr = _mm_aesenc_si128(ctr, RK(4));
	ctr = _mm_aesenc_si128(ctr, RK(5));
	ctr = _mm_aesenc_si128(ctr, RK(6));
	ctr = _mm_aesenc_si128(ctr, RK(7));
	ctr = _mm_aesenc_si128(ctr, RK(8));
	ctr = _mm_aesenc_si128(ctr, RK(9));
	ctr = _mm_aesenc_si128(ctr, RK(10));
	ctr = _mm_aesenc_si128(ctr, RK(11));
	ctr = _mm_aesenc_si128(ctr, RK(12));
	ctr = _mm_aesenc_si128(ctr, RK(13));
	ctr = _mm_aesenclast_si128(ctr, RK(14));

	// * xor block (encrypted ctr) with input
	// load input
	in_vec = _mm_loadu_si128(ASC__m128iu(in));
	// xor
	ctr = _mm_xor_si128(ctr, in_vec);
	// load result into output
	_mm_storeu_si128(AS__m128iu(out), ctr);
}

void SHARED_LIB AESNI_Encrypt(const void *__restrict handle, const void *in, void *out, u32 initialCounter, u64 size)
{
	// pre-func
	handle = ASSUME_ALIGNED(handle, AES_HANDLE_ALIGN);
	size = size >> BLOCK_SIZE_SHIFT;

	// vars
	u64 block_i;
	__m128i ctr, block, inblock;
	// consts
	const __m128i one = _mm_set_epi32(1, 0, 0, 0);
#ifdef __Aes__Increment_Counter_BE
	const __m128i swapmask = _mm_setr_epi8(SWAPMASK_VEC128_LOW32);
#endif //__Aes__Increment_Counter_BE

	// * load iv
	ctr = _mm_load_si128(ASC__m128iu(handle) + AES_HANDLE_CTR_STARTV128);

	// * add initial counter
#ifdef __Aes__Increment_Counter_BE
	ctr = _mm_shuffle_epi8(ctr, swapmask);
#endif //__Aes__Increment_Counter_BE
	ctr = _mm_add_epi32(ctr, _mm_set_epi32(initialCounter, 0, 0, 0));
#ifdef __Aes__Increment_Counter_BE
	ctr = _mm_shuffle_epi8(ctr, swapmask);
#endif //__Aes__Increment_Counter_BE

	// * encrypt blocks
	for (block_i = 0; block_i < size; block_i++)
	{
		// * load current ctr
		block = ctr;

		// * encrypt block (ctr)
		block = _mm_xor_si128(block, RK(0));
		block = _mm_aesenc_si128(block, RK(1));
		block = _mm_aesenc_si128(block, RK(2));
		block = _mm_aesenc_si128(block, RK(3));
		block = _mm_aesenc_si128(block, RK(4));
		block = _mm_aesenc_si128(block, RK(5));
		block = _mm_aesenc_si128(block, RK(6));
		block = _mm_aesenc_si128(block, RK(7));
		block = _mm_aesenc_si128(block, RK(8));
		block = _mm_aesenc_si128(block, RK(9));
		block = _mm_aesenc_si128(block, RK(10));
		block = _mm_aesenc_si128(block, RK(11));
		block = _mm_aesenc_si128(block, RK(12));
		block = _mm_aesenc_si128(block, RK(13));
		block = _mm_aesenclast_si128(block, RK(14));

		// * xor block (encrypted ctr) with input
		// load input
		inblock = _mm_loadu_si128(ASC__m128iu(in) + block_i);
		// xor
		block = _mm_xor_si128(block, inblock);
		// load result into output
		_mm_storeu_si128(AS__m128iu(out) + block_i, block);

		// * increment ctr
#ifdef __Aes__Increment_Counter_BE
		ctr = _mm_shuffle_epi8(ctr, swapmask);
#endif //__Aes__Increment_Counter_BE
		ctr = _mm_add_epi32(ctr, one);
#ifdef __Aes__Increment_Counter_BE
		ctr = _mm_shuffle_epi8(ctr, swapmask);
#endif //__Aes__Increment_Counter_BE
	}
}
