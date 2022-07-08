#include "AESDF.h"

#include "..\AES_Consts\AES_Basic.h"
#include "AES_Sbox.h"

#include "Macro.h"
#include "Types.h"

#define F(ek32, iw, rcon)                              \
	ek32[iw] =                                         \
		((Sbox[((ek32[iw - 1]) >> 8) & 0xff]) |        \
		 (Sbox[((ek32[iw - 1]) >> 16) & 0xff] << 8) |  \
		 (Sbox[((ek32[iw - 1]) >> 24) & 0xff] << 16) | \
		 (Sbox[((ek32[iw - 1]) >> 0) & 0xff] << 24)) ^ \
		ek32[iw - 8] ^ rcon

#define G(ek32, iw)                                     \
	ek32[iw] =                                          \
		((Sbox[((ek32[iw - 1]) >> 0) & 0xff]) |         \
		 (Sbox[((ek32[iw - 1]) >> 8) & 0xff] << 8) |    \
		 (Sbox[((ek32[iw - 1]) >> 16) & 0xff] << 16) |  \
		 (Sbox[((ek32[iw - 1]) >> 24) & 0xff] << 24)) ^ \
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

void SHARED_LIB AESDF_SetKey(void *__restrict handle, const void *__restrict key)
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

inline static u8 mul1(const u8 v)
{
	return v;
}
inline static u8 mul2(const u8 v)
{
	return (v << 1) ^ (0x11b & -(v >> 7));
}
inline static u8 mul3(const u8 v)
{
	return mul2(v) ^ v;
}

#define TMP0(i) tmp[i + 0]
#define TMP1(i) tmp[i + 16]

#define GETIV32(i) ((((const u32 *)handle))[i + AES_HANDLE_CTR_STARTW])
#define TMP0W(i) ((u32 *)tmp)[i]
#define RKW(i) ((u32 *)rk)[i]

void SHARED_LIB AESDF_EncryptBlock(const void *__restrict handle, const void *in, void *out, u32 initialCounter)
{
	// pre-func
	handle = ASSUME_ALIGNED(handle, AES_HANDLE_ALIGN);

	// vars
	uiter round, i;
	u8 tmp[BLOCK_SIZE * 2] ALIGNED(AES_HANDLE_ALIGN);
	// converts
	const u8 *rk = (const u8 *)handle + AES_HANDLE_EKEY_START;
	const u8 *pt = (const u8 *)in;
	u8 *ct = (u8 *)out;

	// * round 0, copy, add initial counter
	TMP0W(0) = GETIV32(0) ^ RKW(0);
	TMP0W(1) = GETIV32(1) ^ RKW(1);
	TMP0W(2) = GETIV32(2) ^ RKW(2);
	TMP0W(3) = (GETIV32(3) + initialCounter) ^ RKW(3);
	rk += BLOCK_SIZE;

	// * round 1 - 13
	for (round = 1; round < ROUNDS; round++)
	{
		for (i = 0; i < BLOCK_SIZE; i++)
		{
			TMP1(i) = Sbox[TMP0(i)];
		}
		TMP0(0) = mul2(TMP1(0)) ^ mul3(TMP1(5)) ^ mul1(TMP1(10)) ^ mul1(TMP1(15)) ^ rk[0];
		TMP0(1) = mul1(TMP1(0)) ^ mul2(TMP1(5)) ^ mul3(TMP1(10)) ^ mul1(TMP1(15)) ^ rk[1];
		TMP0(2) = mul1(TMP1(0)) ^ mul1(TMP1(5)) ^ mul2(TMP1(10)) ^ mul3(TMP1(15)) ^ rk[2];
		TMP0(3) = mul3(TMP1(0)) ^ mul1(TMP1(5)) ^ mul1(TMP1(10)) ^ mul2(TMP1(15)) ^ rk[3];
		TMP0(4) = mul2(TMP1(4)) ^ mul3(TMP1(9)) ^ mul1(TMP1(14)) ^ mul1(TMP1(3)) ^ rk[4];
		TMP0(5) = mul1(TMP1(4)) ^ mul2(TMP1(9)) ^ mul3(TMP1(14)) ^ mul1(TMP1(3)) ^ rk[5];
		TMP0(6) = mul1(TMP1(4)) ^ mul1(TMP1(9)) ^ mul2(TMP1(14)) ^ mul3(TMP1(3)) ^ rk[6];
		TMP0(7) = mul3(TMP1(4)) ^ mul1(TMP1(9)) ^ mul1(TMP1(14)) ^ mul2(TMP1(3)) ^ rk[7];
		TMP0(8) = mul2(TMP1(8)) ^ mul3(TMP1(13)) ^ mul1(TMP1(2)) ^ mul1(TMP1(7)) ^ rk[8];
		TMP0(9) = mul1(TMP1(8)) ^ mul2(TMP1(13)) ^ mul3(TMP1(2)) ^ mul1(TMP1(7)) ^ rk[9];
		TMP0(10) = mul1(TMP1(8)) ^ mul1(TMP1(13)) ^ mul2(TMP1(2)) ^ mul3(TMP1(7)) ^ rk[10];
		TMP0(11) = mul3(TMP1(8)) ^ mul1(TMP1(13)) ^ mul1(TMP1(2)) ^ mul2(TMP1(7)) ^ rk[11];
		TMP0(12) = mul2(TMP1(12)) ^ mul3(TMP1(1)) ^ mul1(TMP1(6)) ^ mul1(TMP1(11)) ^ rk[12];
		TMP0(13) = mul1(TMP1(12)) ^ mul2(TMP1(1)) ^ mul3(TMP1(6)) ^ mul1(TMP1(11)) ^ rk[13];
		TMP0(14) = mul1(TMP1(12)) ^ mul1(TMP1(1)) ^ mul2(TMP1(6)) ^ mul3(TMP1(11)) ^ rk[14];
		TMP0(15) = mul3(TMP1(12)) ^ mul1(TMP1(1)) ^ mul1(TMP1(6)) ^ mul2(TMP1(11)) ^ rk[15];
		rk += BLOCK_SIZE;
	}

	// * round 14 (last), copy to output
	ct[0] = Sbox[TMP0(0)] ^ rk[0] ^ pt[0];
	ct[1] = Sbox[TMP0(5)] ^ rk[1] ^ pt[1];
	ct[2] = Sbox[TMP0(10)] ^ rk[2] ^ pt[2];
	ct[3] = Sbox[TMP0(15)] ^ rk[3] ^ pt[3];
	ct[4] = Sbox[TMP0(4)] ^ rk[4] ^ pt[4];
	ct[5] = Sbox[TMP0(9)] ^ rk[5] ^ pt[5];
	ct[6] = Sbox[TMP0(14)] ^ rk[6] ^ pt[6];
	ct[7] = Sbox[TMP0(3)] ^ rk[7] ^ pt[7];
	ct[8] = Sbox[TMP0(8)] ^ rk[8] ^ pt[8];
	ct[9] = Sbox[TMP0(13)] ^ rk[9] ^ pt[9];
	ct[10] = Sbox[TMP0(2)] ^ rk[10] ^ pt[10];
	ct[11] = Sbox[TMP0(7)] ^ rk[11] ^ pt[11];
	ct[12] = Sbox[TMP0(12)] ^ rk[12] ^ pt[12];
	ct[13] = Sbox[TMP0(1)] ^ rk[13] ^ pt[13];
	ct[14] = Sbox[TMP0(6)] ^ rk[14] ^ pt[14];
	ct[15] = Sbox[TMP0(11)] ^ rk[15] ^ pt[15];
}

#define GETIV8(i) ((((const u8 *)handle) + AES_HANDLE_CTR_START)[i])
// 16 temp0, 16 temp1, 16 ctr, 4 counter_ark
#define TMP_SIZE (16 + 16 + 16 + 4)
#define CTR(i) tmp[i + 32]
#define COUNTER_ARK_SB(i) tmp[i + 48]
#define COUNTER(i) ((u8 *)(&initialCounter))[i]
#define COUNTERW (initialCounter)

void SHARED_LIB AESDF_Encrypt(const void *__restrict handle, const void *in, void *out, u32 initialCounter, u64 size)
{
	// pre-func
	size = size >> BLOCK_SIZE_SHIFT;
	handle = ASSUME_ALIGNED(handle, AES_HANDLE_ALIGN);

	// vars
	u64 block_i;
	uiter i, round;
	u8 tmp[TMP_SIZE] ALIGNED(AES_HANDLE_ALIGN);
	// converts
	const u8 *rk = (const u8 *)handle + AES_HANDLE_EKEY_START;
	const u8 *pt = (const u8 *)in;
	u8 *ct = (u8 *)out;

	// * load iv, pre-compute round 0 + SB (from round 1) and store at buffer
	for (u64 i = 0; i < BLOCK_SIZE - 4; i++)
	{
		TMP0(i) = Sbox[(GETIV8(i) ^ rk[i])];
	}

	// * add initial counter and store
#ifdef __Aes__Increment_Counter_BE
	*((u32 *)COUNTER_P) = BSWAP32(BSWAP32(GETIV32(3)) + initialCounter);
#else  // LittleEndian
	COUNTERW = GETIV32(3) + initialCounter;
#endif //__Aes__Increment_Counter_BE

	// * pre-compute round 1 and store at buffer
	CTR(0) = mul2(TMP0(0)) ^ mul3(TMP0(5)) ^ mul1(TMP0(10)) ^ rk[0 + BLOCK_SIZE];	// ^ mul1(TMP0(15]) (TMP0(x] is sboxed and XORed with rk[0]) <--row 0
	CTR(1) = mul1(TMP0(0)) ^ mul2(TMP0(5)) ^ mul3(TMP0(10)) ^ rk[1 + BLOCK_SIZE];	// ^ mul1(TMP0(15]) (TMP0(x] is sboxed and XORed with rk[0])
	CTR(2) = mul1(TMP0(0)) ^ mul1(TMP0(5)) ^ mul2(TMP0(10)) ^ rk[2 + BLOCK_SIZE];	// ^ mul3(TMP0(15]) (TMP0(x] is sboxed and XORed with rk[0])
	CTR(3) = mul3(TMP0(0)) ^ mul1(TMP0(5)) ^ mul1(TMP0(10)) ^ rk[3 + BLOCK_SIZE];	// ^ mul2(TMP0(15]) (TMP0(x] is sboxed and XORed with rk[0])
	CTR(4) = mul2(TMP0(4)) ^ mul3(TMP0(9)) ^ mul1(TMP0(3)) ^ rk[4 + BLOCK_SIZE];	// ^ mul1(TMP0(14]) (TMP0(x] is sboxed and XORed with rk[0]) <--row 1
	CTR(5) = mul1(TMP0(4)) ^ mul2(TMP0(9)) ^ mul1(TMP0(3)) ^ rk[5 + BLOCK_SIZE];	// ^ mul3(TMP0(14]) (TMP0(x] is sboxed and XORed with rk[0])
	CTR(6) = mul1(TMP0(4)) ^ mul1(TMP0(9)) ^ mul3(TMP0(3)) ^ rk[6 + BLOCK_SIZE];	// ^ mul2(TMP0(14]) (TMP0(x] is sboxed and XORed with rk[0])
	CTR(7) = mul3(TMP0(4)) ^ mul1(TMP0(9)) ^ mul2(TMP0(3)) ^ rk[7 + BLOCK_SIZE];	// ^ mul1(TMP0(14]) (TMP0(x] is sboxed and XORed with rk[0])
	CTR(8) = mul2(TMP0(8)) ^ mul1(TMP0(2)) ^ mul1(TMP0(7)) ^ rk[8 + BLOCK_SIZE];	// ^ mul3(TMP0(13]) (TMP0(x] is sboxed and XORed with rk[0]) <--row 2
	CTR(9) = mul1(TMP0(8)) ^ mul3(TMP0(2)) ^ mul1(TMP0(7)) ^ rk[9 + BLOCK_SIZE];	// ^ mul2(TMP0(13]) (TMP0(x] is sboxed and XORed with rk[0])
	CTR(10) = mul1(TMP0(8)) ^ mul2(TMP0(2)) ^ mul3(TMP0(7)) ^ rk[10 + BLOCK_SIZE];	// ^ mul1(TMP0(13]) (TMP0(x] is sboxed and XORed with rk[0])
	CTR(11) = mul3(TMP0(8)) ^ mul1(TMP0(2)) ^ mul2(TMP0(7)) ^ rk[11 + BLOCK_SIZE];	// ^ mul1(TMP0(13]) (TMP0(x] is sboxed and XORed with rk[0])
	CTR(12) = mul3(TMP0(1)) ^ mul1(TMP0(6)) ^ mul1(TMP0(11)) ^ rk[12 + BLOCK_SIZE]; // ^ mul2(TMP0(12]) (TMP0(x] is sboxed and XORed with rk[0]) <--row 3
	CTR(13) = mul2(TMP0(1)) ^ mul3(TMP0(6)) ^ mul1(TMP0(11)) ^ rk[13 + BLOCK_SIZE]; // ^ mul1(TMP0(12]) (TMP0(x] is sboxed and XORed with rk[0])
	CTR(14) = mul1(TMP0(1)) ^ mul2(TMP0(6)) ^ mul3(TMP0(11)) ^ rk[14 + BLOCK_SIZE]; // ^ mul1(TMP0(12]) (TMP0(x] is sboxed and XORed with rk[0])
	CTR(15) = mul1(TMP0(1)) ^ mul1(TMP0(6)) ^ mul2(TMP0(11)) ^ rk[15 + BLOCK_SIZE]; // ^ mul3(TMP0(12]) (TMP0(x] is sboxed and XORed with rk[0])

	// * encrypt blocks
	for (block_i = 0; block_i < size; ++block_i)
	{
		// * round 0 - 1
		// load current ark0+sb1 counter
		for (i = 0; i < 4; i++)
		{
			COUNTER_ARK_SB(i) = Sbox[(COUNTER(i) ^ rk[i + 12])];
		}
		TMP0(0) = CTR(0) ^ mul1(COUNTER_ARK_SB(3)); // 15
		TMP0(1) = CTR(1) ^ mul1(COUNTER_ARK_SB(3));
		TMP0(2) = CTR(2) ^ mul3(COUNTER_ARK_SB(3));
		TMP0(3) = CTR(3) ^ mul2(COUNTER_ARK_SB(3));
		TMP0(4) = CTR(4) ^ mul1(COUNTER_ARK_SB(2)); // 14
		TMP0(5) = CTR(5) ^ mul3(COUNTER_ARK_SB(2));
		TMP0(6) = CTR(6) ^ mul2(COUNTER_ARK_SB(2));
		TMP0(7) = CTR(7) ^ mul1(COUNTER_ARK_SB(2));
		TMP0(8) = CTR(8) ^ mul3(COUNTER_ARK_SB(1)); // 13
		TMP0(9) = CTR(9) ^ mul2(COUNTER_ARK_SB(1));
		TMP0(10) = CTR(10) ^ mul1(COUNTER_ARK_SB(1));
		TMP0(11) = CTR(11) ^ mul1(COUNTER_ARK_SB(1));
		TMP0(12) = CTR(12) ^ mul2(COUNTER_ARK_SB(0)); // 12
		TMP0(13) = CTR(13) ^ mul1(COUNTER_ARK_SB(0));
		TMP0(14) = CTR(14) ^ mul1(COUNTER_ARK_SB(0));
		TMP0(15) = CTR(15) ^ mul3(COUNTER_ARK_SB(0));
		rk += BLOCK_SIZE * 2;

		// * round 2 - 13
		for (round = 2; round < ROUNDS; round++)
		{
			for (i = 0; i < BLOCK_SIZE; i++)
			{
				TMP1(i) = Sbox[TMP0(i)];
			}
			TMP0(0) = mul2(TMP1(0)) ^ mul3(TMP1(5)) ^ mul1(TMP1(10)) ^ mul1(TMP1(15)) ^ rk[0];
			TMP0(1) = mul1(TMP1(0)) ^ mul2(TMP1(5)) ^ mul3(TMP1(10)) ^ mul1(TMP1(15)) ^ rk[1];
			TMP0(2) = mul1(TMP1(0)) ^ mul1(TMP1(5)) ^ mul2(TMP1(10)) ^ mul3(TMP1(15)) ^ rk[2];
			TMP0(3) = mul3(TMP1(0)) ^ mul1(TMP1(5)) ^ mul1(TMP1(10)) ^ mul2(TMP1(15)) ^ rk[3];
			TMP0(4) = mul2(TMP1(4)) ^ mul3(TMP1(9)) ^ mul1(TMP1(14)) ^ mul1(TMP1(3)) ^ rk[4];
			TMP0(5) = mul1(TMP1(4)) ^ mul2(TMP1(9)) ^ mul3(TMP1(14)) ^ mul1(TMP1(3)) ^ rk[5];
			TMP0(6) = mul1(TMP1(4)) ^ mul1(TMP1(9)) ^ mul2(TMP1(14)) ^ mul3(TMP1(3)) ^ rk[6];
			TMP0(7) = mul3(TMP1(4)) ^ mul1(TMP1(9)) ^ mul1(TMP1(14)) ^ mul2(TMP1(3)) ^ rk[7];
			TMP0(8) = mul2(TMP1(8)) ^ mul3(TMP1(13)) ^ mul1(TMP1(2)) ^ mul1(TMP1(7)) ^ rk[8];
			TMP0(9) = mul1(TMP1(8)) ^ mul2(TMP1(13)) ^ mul3(TMP1(2)) ^ mul1(TMP1(7)) ^ rk[9];
			TMP0(10) = mul1(TMP1(8)) ^ mul1(TMP1(13)) ^ mul2(TMP1(2)) ^ mul3(TMP1(7)) ^ rk[10];
			TMP0(11) = mul3(TMP1(8)) ^ mul1(TMP1(13)) ^ mul1(TMP1(2)) ^ mul2(TMP1(7)) ^ rk[11];
			TMP0(12) = mul2(TMP1(12)) ^ mul3(TMP1(1)) ^ mul1(TMP1(6)) ^ mul1(TMP1(11)) ^ rk[12];
			TMP0(13) = mul1(TMP1(12)) ^ mul2(TMP1(1)) ^ mul3(TMP1(6)) ^ mul1(TMP1(11)) ^ rk[13];
			TMP0(14) = mul1(TMP1(12)) ^ mul1(TMP1(1)) ^ mul2(TMP1(6)) ^ mul3(TMP1(11)) ^ rk[14];
			TMP0(15) = mul3(TMP1(12)) ^ mul1(TMP1(1)) ^ mul1(TMP1(6)) ^ mul2(TMP1(11)) ^ rk[15];
			rk += BLOCK_SIZE;
		}

		// * round 14 (last), copy to output
		ct[0] = Sbox[TMP0(0)] ^ rk[0] ^ pt[0];
		ct[1] = Sbox[TMP0(5)] ^ rk[1] ^ pt[1];
		ct[2] = Sbox[TMP0(10)] ^ rk[2] ^ pt[2];
		ct[3] = Sbox[TMP0(15)] ^ rk[3] ^ pt[3];
		ct[4] = Sbox[TMP0(4)] ^ rk[4] ^ pt[4];
		ct[5] = Sbox[TMP0(9)] ^ rk[5] ^ pt[5];
		ct[6] = Sbox[TMP0(14)] ^ rk[6] ^ pt[6];
		ct[7] = Sbox[TMP0(3)] ^ rk[7] ^ pt[7];
		ct[8] = Sbox[TMP0(8)] ^ rk[8] ^ pt[8];
		ct[9] = Sbox[TMP0(13)] ^ rk[9] ^ pt[9];
		ct[10] = Sbox[TMP0(2)] ^ rk[10] ^ pt[10];
		ct[11] = Sbox[TMP0(7)] ^ rk[11] ^ pt[11];
		ct[12] = Sbox[TMP0(12)] ^ rk[12] ^ pt[12];
		ct[13] = Sbox[TMP0(1)] ^ rk[13] ^ pt[13];
		ct[14] = Sbox[TMP0(6)] ^ rk[14] ^ pt[14];
		ct[15] = Sbox[TMP0(11)] ^ rk[15] ^ pt[15];

		// * increment counter
#ifdef __Aes__Increment_Counter_BE
		*((u32 *)COUNTER_P) = BSWAP32(BSWAP32(*((u32 *)COUNTER_P)) + 1);
#else  // LittleEndian
		++COUNTERW;
#endif //__Aes__Increment_Counter_BE

		// * block encrypted, move pointers
		rk -= (EKEY_SIZE - BLOCK_SIZE);
		ct += BLOCK_SIZE;
		pt += BLOCK_SIZE;
	}
	// * input encrypted
}
