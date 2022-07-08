#ifndef __AES_Handle__
#define __AES_Handle__

#include "Dll_Basic.h"

void SHARED_LIB AES_CreateHandle(void **handle);
void SHARED_LIB AES_SetIV(void *handle, const void *iv);
void SHARED_LIB AES_DestroyHandle(void *handle);

#endif //__AES_Handle__