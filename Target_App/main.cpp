#include <iostream>
#include <windows.h>
#include <psapi.h>
void *GetBaseAddressFromPID(DWORD piwhd)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, piwhd);
    if (hProcess == NULL)
    {
        std::cerr << "Unable to open process with PID " << piwhd << std::endl;
        return nullptr;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        void *baseAddress = reinterpret_cast<void *>(hMods[0]);
        CloseHandle(hProcess); // Close the handle to the process
        return baseAddress;
    }
    else
    {
        std::cerr << "Unable to enumerate process modules." << std::endl;
        CloseHandle(hProcess);
        return nullptr;
    }
}

int Test_Func()
{
    return 200;
}

int Test_Func2(int x, int y)
{
    return SetCursorPos(x, y);
}
int main()
{
    DWORD pid = GetCurrentProcessId();
    void *baseAddr = GetBaseAddressFromPID(pid);
    void *First_Func = (void *)Test_Func;
    void *Second_Func = (void *)Test_Func2;
    DWORD_PTR First_Offset = (DWORD_PTR)First_Func - (DWORD_PTR)baseAddr;
    DWORD_PTR Second_Offset = (DWORD_PTR)Second_Func - (DWORD_PTR)baseAddr;
    std::cout << "Base address of module: " << baseAddr << std::endl;
    std::cout << "1st Offset: 0x" << std::hex << First_Offset << std::endl;
    std::cout << "2nd Offset: 0x" << std::hex << Second_Offset << std::endl;
    std::cin.get();
    while (true)
    {
        std::cout << (int)Test_Func() << std::endl;
    }
    return 0;
}
