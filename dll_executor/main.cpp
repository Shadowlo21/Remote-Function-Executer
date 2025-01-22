#include <Windows.h>
#include "MinHook/include/MinHook.h"
#include <cstdio>
#include <string>
inline bool TargetApp()
{
    DWORD base = (DWORD)GetModuleHandle(L"Project1.exe");
    DWORD Target_Base = (DWORD)GetModuleHandle(0);
    if (base != Target_Base)
        return false;
    return true;
}


inline int New_Func() {
    return 0;
}
#define Msg(x,y)  MessageBoxA(0, x, y, MB_OK);
inline namespace Memory {
    template<typename T>
    inline T read_memory(void* targetFunctionAddr)
    {
        auto fn = reinterpret_cast<T(*)()>(targetFunctionAddr);
        return fn(); //add argus if there is 
    }
    inline void write_new_func(void** targetFunctionAddr)
    {
        *targetFunctionAddr = reinterpret_cast<void*>(&New_Func);
    }
    template <typename T, typename... Args>
    inline T CallFunc(void* targetFunctionAddr, Args... args) {
        auto fn = reinterpret_cast<T(*)(Args...)>(targetFunctionAddr);
        return fn(args...);
    }

}

inline void Hook() {
    Msg("Injected", "[Dev]");
    PVOID Target_Base = (PVOID)GetModuleHandle(0);
    Msg(std::to_string((uintptr_t)Target_Base).c_str(), "Base Address");
    uintptr_t* targetFunctionAddr = (uintptr_t*)((uintptr_t)Target_Base + 0x1110); //Addr of the func that return int
    uintptr_t result = Memory::read_memory<uintptr_t>(targetFunctionAddr);
    Msg(std::to_string(result).c_str(), "Before Hooking"); // output should be 500(int ) or 1f4 (hex)
    Memory::write_new_func(reinterpret_cast<void**>(&targetFunctionAddr));
    result = Memory::read_memory<uintptr_t>(targetFunctionAddr);
    Msg(std::to_string(result).c_str(), "After Hooking"); //output should be 0
    uintptr_t* targetMouse_MouseFunctionAddr = (uintptr_t*)((uintptr_t)Target_Base + 0x1120); //Addr of the func that moves the mouse
    CallFunc<uintptr_t*, int, int>(targetMouse_MouseFunctionAddr, 500, 700); //Moves the mouse to test
}

BOOL __stdcall DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        if (TargetApp()) {
            (AllocConsole)();
            (freopen)(("conin$"), ("r"), stdin);
            (freopen)(("conout$"), ("w"), stdout);
            (freopen)(("conout$"), ("w"), stderr);
            Hook();
            return 0;
        }
        else {
            return 1;
        }
    }
    return TRUE;
}
