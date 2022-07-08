#include "AesTT.h"

#include "..\AES_Consts\Aes_Basic.h"
#include "Aes_TTables.h"

#include "Types.h"
#include "Macro.h"

#define F(ek32, iw, rcon)                                     \
	ek32[iw] =                                                \
		((Te3[((ek32[iw - 1]) >> 8) & 0xff] & 0x000000ffU) |  \
		 (Te3[((ek32[iw - 1]) >> 16) & 0xff] & 0x0000ff00U) | \
		 (Te1[((ek32[iw - 1]) >> 24) & 0xff] & 0x00ff0000U) | \
		 (Te1[((ek32[iw - 1]) >> 0) & 0xff] & 0xff000000U)) ^ \
		ek32[iw - 8] ^ rcon

#define G(ek32, iw)                                            \
	ek32[iw] =                                                 \
		((Te3[((ek32[iw - 1]) >> 0) & 0xff] & 0x000000ffU) |   \
		 (Te3[((ek32[iw - 1]) >> 8) & 0xff] & 0x0000ff00U) |   \
		 (Te1[((ek32[iw - 1]) >> 16) & 0xff] & 0x00ff0000U) |  \
		 (Te1[((ek32[iw - 1]) >> 24) & 0xff] & 0xff000000U)) ^ \
		ek32[iw - 8]

#define X(ek32, iw) ek32[iw] = ek32[iw - 1] ^ ek32[iw - 8]

#define KEYGEN_1(ekw, i128, rconw) \
	F(ekw, (i128)*4 + 0, rconw);   \
	X(ekw, (i128)*4 + 1);          \
	X(ekw, (i128)*4 + 2);          \
	X(ekw, (i128)*4 + 3)

#define KEYGEN_2(ekw, i128) \
	G(ekw, (i128)*4 + 0);   \
	X(ekw, (i128)*4 + 1);   \
	X(ekw, (i128)*4 + 2);   \
	X(ekw, (i128)*4 + 3)

void SHARED_LIB AESTT_SetKey(void *__restrict handle, const void *__restrict key)
{
	handle = ASSUME_ALIGNED(handle, AES_HANDLE_ALIGN);
	u32 *ek32 = (u32 *)handle + AES_HANDLE_EKEY_STARTW;
	// copy key (0-7 words)
	for (uiter i = 0; i < KEY_SIZEW; i++)
	{
		ek32[i] = GET32(key, i);
	}
	KEYGEN_1(ek32, 2, 0x01);
	KEYGEN_2(ek32, 3);
	KEYGEN_1(ek32, 4, 0x02);
	KEYGEN_2(ek32, 5);
	KEYGEN_1(ek32, 6, 0x04);
	KEYGEN_2(ek32, 7);
	KEYGEN_1(ek32, 8, 0x08);
	KEYGEN_2(ek32, 9);
	KEYGEN_1(ek32, 10, 0x10);
	KEYGEN_2(ek32, 11);
	KEYGEN_1(ek32, 12, 0x20);
	KEYGEN_2(ek32, 13);
	KEYGEN_1(ek32, 14, 0x40);
}

#define GETIV32(i) ((((const u32 *)handle))[i + AES_HANDLE_CTR_STARTW])

#define TMP0W(i) tmpw[i + 0]
#define TMP1W(i) tmpw[i + 4]

void SHARED_LIB AESTT_EncryptBlock(const void *__restrict handle, const void *in, void *out, u32 initialCounter)
{
	// pre-func
	handle = ASSUME_ALIGNED(handle, AES_HANDLE_ALIGN);

	// vars
	uiter round;
	u32 tmpw[BLOCK_SIZEW * 2] ALIGNED(AES_HANDLE_ALIGN);
	// converts
	const u32 *rkw = (const u32 *)handle + AES_HANDLE_EKEY_STARTW;
	const u32 *ptw = (const u32 *)in;
	u32 *ctw = (u32 *)out;

	// * round 0, copy, add initial counter
	TMP0W(0) = GETIV32(0) ^ rkw[0];
	TMP0W(1) = GETIV32(1) ^ rkw[1];
	TMP0W(2) = GETIV32(2) ^ rkw[2];
	TMP0W(3) = (GETIV32(3) + initialCounter) ^ rkw[3];
	rkw += BLOCK_SIZEW;

	// * round 1 - 12
	for (round = 2 / 2; round < (ROUNDS / 2); round++)
	{
		// round
		TMP1W(0) = Te0[TMP0W(0) & 0x000000ffU] ^ Te1[(TMP0W(1) >> 8U) & 0x000000ffU] ^ Te2[(TMP0W(2) >> 16U) & 0x000000ffU] ^ Te3[(TMP0W(3) >> 24U)] ^ rkw[0];
		TMP1W(1) = Te0[TMP0W(1) & 0x000000ffU] ^ Te1[(TMP0W(2) >> 8U) & 0x000000ffU] ^ Te2[(TMP0W(3) >> 16U) & 0x000000ffU] ^ Te3[(TMP0W(0) >> 24U)] ^ rkw[1];
		TMP1W(2) = Te0[TMP0W(2) & 0x000000ffU] ^ Te1[(TMP0W(3) >> 8U) & 0x000000ffU] ^ Te2[(TMP0W(0) >> 16U) & 0x000000ffU] ^ Te3[(TMP0W(1) >> 24U)] ^ rkw[2];
		TMP1W(3) = Te0[TMP0W(3) & 0x000000ffU] ^ Te1[(TMP0W(0) >> 8U) & 0x000000ffU] ^ Te2[(TMP0W(1) >> 16U) & 0x000000ffU] ^ Te3[(TMP0W(2) >> 24U)] ^ rkw[3];
		// round + 1
		TMP0W(0) = Te0[TMP1W(0) & 0x000000ffU] ^ Te1[(TMP1W(1) >> 8U) & 0x000000ffU] ^ Te2[(TMP1W(2) >> 16U) & 0x000000ffU] ^ Te3[(TMP1W(3) >> 24U)] ^ rkw[4];
		TMP0W(1) = Te0[TMP1W(1) & 0x000000ffU] ^ Te1[(TMP1W(2) >> 8U) & 0x000000ffU] ^ Te2[(TMP1W(3) >> 16U) & 0x000000ffU] ^ Te3[(TMP1W(0) >> 24U)] ^ rkw[5];
		TMP0W(2) = Te0[TMP1W(2) & 0x000000ffU] ^ Te1[(TMP1W(3) >> 8U) & 0x000000ffU] ^ Te2[(TMP1W(0) >> 16U) & 0x000000ffU] ^ Te3[(TMP1W(1) >> 24U)] ^ rkw[6];
		TMP0W(3) = Te0[TMP1W(3) & 0x000000ffU] ^ Te1[(TMP1W(0) >> 8U) & 0x000000ffU] ^ Te2[(TMP1W(1) >> 16U) & 0x000000ffU] ^ Te3[(TMP1W(2) >> 24U)] ^ rkw[7];
		rkw += (BLOCK_SIZEW * 2);
	}

	// * round 13
	TMP1W(0) = Te0[TMP0W(0) & 0x000000ffU] ^ Te1[(TMP0W(1) >> 8U) & 0x000000ffU] ^ Te2[(TMP0W(2) >> 16U) & 0x000000ffU] ^ Te3[(TMP0W(3) >> 24U)] ^ rkw[0];
	TMP1W(1) = Te0[TMP0W(1) & 0x000000ffU] ^ Te1[(TMP0W(2) >> 8U) & 0x000000ffU] ^ Te2[(TMP0W(3) >> 16U) & 0x000000ffU] ^ Te3[(TMP0W(0) >> 24U)] ^ rkw[1];
	TMP1W(2) = Te0[TMP0W(2) & 0x000000ffU] ^ Te1[(TMP0W(3) >> 8U) & 0x000000ffU] ^ Te2[(TMP0W(0) >> 16U) & 0x000000ffU] ^ Te3[(TMP0W(1) >> 24U)] ^ rkw[2];
	TMP1W(3) = Te0[TMP0W(3) & 0x000000ffU] ^ Te1[(TMP0W(0) >> 8U) & 0x000000ffU] ^ Te2[(TMP0W(1) >> 16U) & 0x000000ffU] ^ Te3[(TMP0W(2) >> 24U)] ^ rkw[3];

	// * round 14 (last), copy to output
	ctw[0] = ptw[0] ^ ((Te3[TMP1W(0) & 0x000000ffU] & 0x000000ffU) | (Te3[(TMP1W(1) >> 8U) & 0x000000ffU] & 0x0000ff00U) | (Te1[(TMP1W(2) >> 16U) & 0x000000ffU] & 0x00ff0000U) | (Te1[(TMP1W(3) >> 24U)] & 0xff000000U)) ^ rkw[4];
	ctw[1] = ptw[1] ^ ((Te3[TMP1W(1) & 0x000000ffU] & 0x000000ffU) | (Te3[(TMP1W(2) >> 8U) & 0x000000ffU] & 0x0000ff00U) | (Te1[(TMP1W(3) >> 16U) & 0x000000ffU] & 0x00ff0000U) | (Te1[(TMP1W(0) >> 24U)] & 0xff000000U)) ^ rkw[5];
	ctw[2] = ptw[2] ^ ((Te3[TMP1W(2) & 0x000000ffU] & 0x000000ffU) | (Te3[(TMP1W(3) >> 8U) & 0x000000ffU] & 0x0000ff00U) | (Te1[(TMP1W(0) >> 16U) & 0x000000ffU] & 0x00ff0000U) | (Te1[(TMP1W(1) >> 24U)] & 0xff000000U)) ^ rkw[6];
	ctw[3] = ptw[3] ^ ((Te3[TMP1W(3) & 0x000000ffU] & 0x000000ffU) | (Te3[(TMP1W(0) >> 8U) & 0x000000ffU] & 0x0000ff00U) | (Te1[(TMP1W(1) >> 16U) & 0x000000ffU] & 0x00ff0000U) | (Te1[(TMP1W(2) >> 24U)] & 0xff000000U)) ^ rkw[7];
}

// 4 temp0, 4 temp1, 4 ctr, 1 counter_ark
#define TMP_SIZEW (4 + 4 + 4 + 1)
#define CTRW(i) tmpw[i + 8]
#define COUNTERW_ARK tmpw[12]
#define COUNTERW (initialCounter)

void SHARED_LIB AESTT_Encrypt(const void *__restrict handle, const void *in, void *out, u32 initialCounter, u64 size)
{
	// pre-func
	size = size >> BLOCK_SIZE_SHIFT;
	handle = ASSUME_ALIGNED(handle, AES_HANDLE_ALIGN);

	// vars
	u64 block_i;
	uiter round;
	u32 tmpw[TMP_SIZEW] ALIGNED(AES_HANDLE_ALIGN);
	// converts
	const u32 *rkw = (const u32 *)handle + AES_HANDLE_EKEY_STARTW;
	const u32 *ptw = (const u32 *)in;
	u32 *ctw = (u32 *)out;

	// * load iv, pre-compute round 0 and store at buffer
	TMP0W(0) = GETIV32(0) ^ rkw[0];
	TMP0W(1) = GETIV32(1) ^ rkw[1];
	TMP0W(2) = GETIV32(2) ^ rkw[2];

	// * add initial counter and store
#ifdef __Aes__Increment_Counter_BE
	COUNTERW = BSWAP32(BSWAP32(GETIV32(3)) + initialCounter);
#else  // LittleEndian
	COUNTERW = GETIV32(3) + initialCounter;
#endif //__Aes__Increment_Counter_BE

	// * pre-compute round 1 and store at buffer
	CTRW(0) = Te0[TMP0W(0) & 0x000000ffU] ^ Te1[(TMP0W(1) >> 8U) & 0x000000ffU] ^ Te2[(TMP0W(2) >> 16U) & 0x000000ffU] ^ rkw[4]; // ^ Te3[(TMP0W(3] >> 24U)]
	CTRW(1) = Te0[TMP0W(1) & 0x000000ffU] ^ Te1[(TMP0W(2) >> 8U) & 0x000000ffU] ^ Te3[(TMP0W(0) >> 24U)] ^ rkw[5];				 // ^ Te2[(TMP0W(3] >> 16U) & 0x000000ffU]
	CTRW(2) = Te0[TMP0W(2) & 0x000000ffU] ^ Te2[(TMP0W(0) >> 16U) & 0x000000ffU] ^ Te3[(TMP0W(1) >> 24U)] ^ rkw[6];				 // ^ Te1[(TMP0W(3] >> 8U) & 0x000000ffU]
	CTRW(3) = Te1[(TMP0W(0) >> 8U) & 0x000000ffU] ^ Te2[(TMP0W(1) >> 16U) & 0x000000ffU] ^ Te3[(TMP0W(2) >> 24U)] ^ rkw[7];		 // ^ Te0[TMP0W(3] & 0x000000ffU]

	// * encrypt blocks
	for (block_i = 0; block_i < size; block_i++)
	{
		// * round 0 - 1
		// load current ark0 counter
		COUNTERW_ARK = COUNTERW ^ rkw[3];
		TMP0W(0) = CTRW(0) ^ Te3[(COUNTERW_ARK >> 24U)];
		TMP0W(1) = CTRW(1) ^ Te2[(COUNTERW_ARK >> 16U) & 0x000000ffU];
		TMP0W(2) = CTRW(2) ^ Te1[(COUNTERW_ARK >> 8U) & 0x000000ffU];
		TMP0W(3) = CTRW(3) ^ Te0[COUNTERW_ARK & 0x000000ffU];
		rkw += BLOCK_SIZEW * 2;

		// * round 2 - 13
		for (round = 2 / 2; round < (ROUNDS / 2); round++)
		{
			// round
			TMP1W(0) = Te0[TMP0W(0) & 0x000000ffU] ^ Te1[(TMP0W(1) >> 8U) & 0x000000ffU] ^ Te2[(TMP0W(2) >> 16U) & 0x000000ffU] ^ Te3[(TMP0W(3) >> 24U)] ^ rkw[0];
			TMP1W(1) = Te0[TMP0W(1) & 0x000000ffU] ^ Te1[(TMP0W(2) >> 8U) & 0x000000ffU] ^ Te2[(TMP0W(3) >> 16U) & 0x000000ffU] ^ Te3[(TMP0W(0) >> 24U)] ^ rkw[1];
			TMP1W(2) = Te0[TMP0W(2) & 0x000000ffU] ^ Te1[(TMP0W(3) >> 8U) & 0x000000ffU] ^ Te2[(TMP0W(0) >> 16U) & 0x000000ffU] ^ Te3[(TMP0W(1) >> 24U)] ^ rkw[2];
			TMP1W(3) = Te0[TMP0W(3) & 0x000000ffU] ^ Te1[(TMP0W(0) >> 8U) & 0x000000ffU] ^ Te2[(TMP0W(1) >> 16U) & 0x000000ffU] ^ Te3[(TMP0W(2) >> 24U)] ^ rkw[3];
			// round + 1
			TMP0W(0) = Te0[TMP1W(0) & 0x000000ffU] ^ Te1[(TMP1W(1) >> 8U) & 0x000000ffU] ^ Te2[(TMP1W(2) >> 16U) & 0x000000ffU] ^ Te3[(TMP1W(3) >> 24U)] ^ rkw[4];
			TMP0W(1) = Te0[TMP1W(1) & 0x000000ffU] ^ Te1[(TMP1W(2) >> 8U) & 0x000000ffU] ^ Te2[(TMP1W(3) >> 16U) & 0x000000ffU] ^ Te3[(TMP1W(0) >> 24U)] ^ rkw[5];
			TMP0W(2) = Te0[TMP1W(2) & 0x000000ffU] ^ Te1[(TMP1W(3) >> 8U) & 0x000000ffU] ^ Te2[(TMP1W(0) >> 16U) & 0x000000ffU] ^ Te3[(TMP1W(1) >> 24U)] ^ rkw[6];
			TMP0W(3) = Te0[TMP1W(3) & 0x000000ffU] ^ Te1[(TMP1W(0) >> 8U) & 0x000000ffU] ^ Te2[(TMP1W(1) >> 16U) & 0x000000ffU] ^ Te3[(TMP1W(2) >> 24U)] ^ rkw[7];
			rkw += (BLOCK_SIZEW * 2);
		}

		// * round 14 (last), copy to output
		ctw[0] = ptw[0] ^ ((Te3[TMP0W(0) & 0x000000ffU] & 0x000000ffU) | (Te3[(TMP0W(1) >> 8U) & 0x000000ffU] & 0x0000ff00U) | (Te1[(TMP0W(2) >> 16U) & 0x000000ffU] & 0x00ff0000U) | (Te1[(TMP0W(3) >> 24U)] & 0xff000000U)) ^ rkw[0];
		ctw[1] = ptw[1] ^ ((Te3[TMP0W(1) & 0x000000ffU] & 0x000000ffU) | (Te3[(TMP0W(2) >> 8U) & 0x000000ffU] & 0x0000ff00U) | (Te1[(TMP0W(3) >> 16U) & 0x000000ffU] & 0x00ff0000U) | (Te1[(TMP0W(0) >> 24U)] & 0xff000000U)) ^ rkw[1];
		ctw[2] = ptw[2] ^ ((Te3[TMP0W(2) & 0x000000ffU] & 0x000000ffU) | (Te3[(TMP0W(3) >> 8U) & 0x000000ffU] & 0x0000ff00U) | (Te1[(TMP0W(0) >> 16U) & 0x000000ffU] & 0x00ff0000U) | (Te1[(TMP0W(1) >> 24U)] & 0xff000000U)) ^ rkw[2];
		ctw[3] = ptw[3] ^ ((Te3[TMP0W(3) & 0x000000ffU] & 0x000000ffU) | (Te3[(TMP0W(0) >> 8U) & 0x000000ffU] & 0x0000ff00U) | (Te1[(TMP0W(1) >> 16U) & 0x000000ffU] & 0x00ff0000U) | (Te1[(TMP0W(2) >> 24U)] & 0xff000000U)) ^ rkw[3];

		// * increment counter
#ifdef __Aes__Increment_Counter_BE
		COUNTERW = BSWAP32(BSWAP32(COUNTERW) + 1);
#else  // LittleEndian
		++COUNTERW;
#endif //__Aes__Increment_Counter_BE

		// * block encrypted, move pointers
		rkw -= (EKEY_SIZEW - BLOCK_SIZEW);
		ctw += BLOCK_SIZEW;
		ptw += BLOCK_SIZEW;
	}
	// * input encrypted
}
