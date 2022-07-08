#ifndef __DLL_Basic__
#define __DLL_Basic__

#ifdef BUILD_DLL
#define SHARED_LIB __declspec(dllexport)
#else
#define SHARED_LIB __declspec(dllimport)
#endif

#endif //__DLL_Basic__