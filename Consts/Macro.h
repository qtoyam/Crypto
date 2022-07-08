#ifndef __Macro__
#define __Macro__

#define GET8(src, i) (((const u8 *)(src))[i])
#define GET32(src, i) (((const u32 *)(src))[i])
#define PUT8(dest, i, v) (((u8 *)(dest))[i] = (v))
#define PUT32(dest, i, v) (((u32 *)(dest))[i] = (v))
#define BSWAP32(v) __builtin_bswap32((v))

#define ASSUME_ALIGNED(pointer, align) (__builtin_assume_aligned((pointer), (align)))
#define ALIGNED(align) __attribute__((aligned(align)))

#define CLEAR_MEMW(mem, length)                                               \
	do                                                                        \
	{                                                                         \
		u32 *volatile CLEAR_MEMW_mem32 = (u32 *volatile)(mem);                \
		for (uiter CLEAR_MEMW_i = 0; CLEAR_MEMW_i < (length); CLEAR_MEMW_i++) \
		{                                                                     \
			CLEAR_MEMW_mem32[CLEAR_MEMW_i] = 0x00000000U;                     \
		}                                                                     \
	} while (0)

#endif //__Macro__