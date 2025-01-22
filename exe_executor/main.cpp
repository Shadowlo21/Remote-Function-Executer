#include <iostream>
#include <Windows.h>
#include <conio.h>
#include <codecvt>
#include <iomanip>
#include <dwmapi.h>
#include <TlHelp32.h>
#include <string>
#include <random>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
inline DWORD get_process_id(
    const LPCWSTR process_name)
{
    HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    DWORD procID = NULL;

    if (handle == INVALID_HANDLE_VALUE)
        return procID;

    PROCESSENTRY32W entry = { 0 };
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(handle, &entry)) {
        if (!_wcsicmp(process_name, entry.szExeFile))
        {
            procID = entry.th32ProcessID;
        }
        else while (Process32NextW(handle, &entry)) {
            if (!_wcsicmp(process_name, entry.szExeFile)) {
                procID = entry.th32ProcessID;
            }
        }
    }

    CloseHandle(handle);
    return procID;
}


uintptr_t GetBaseAddressFromPID(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        std::cerr << "Unable to open process with PID " << pid << std::endl;
        return 0;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        void* baseAddress = reinterpret_cast<void*>(hMods[0]);
        CloseHandle(hProcess);  // Close the handle to the process
        return (uintptr_t)baseAddress;
    }
    else {
        std::cerr << "Unable to enumerate process modules." << std::endl;
        CloseHandle(hProcess);
        return 0;
    }
}






void Execute_Function(HANDLE hTargetProc, uintptr_t targetFunctionAddr) {
    // Allocate memory in the target process for the return value
    LPVOID pRemoteMemory = VirtualAllocEx(hTargetProc, nullptr, sizeof(int), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMemory) {
        std::cerr << "Failed to allocate memory in target process." << std::endl;
        CloseHandle(hTargetProc);
        return;
    }

    // Shellcode to call the target function and store the return value
    unsigned char shellcode[] = {
        0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 0x28 (align stack)
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, targetFunctionAddr
        0xFF, 0xD0,                                                 // call rax
        0x48, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov [pRemoteMemory], rax
        0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 0x28 (restore stack)
        0xC3                                                        // ret
    };

    // Patch the shellcode with the target function address and return value memory address
    *(uintptr_t*)(shellcode + 6) = targetFunctionAddr;              // Replace 0x00000000 with targetFunctionAddr
    *(uintptr_t*)(shellcode + 18) = (uintptr_t)pRemoteMemory;       // Replace 0x00000000 with pRemoteMemory

    // Allocate memory in the target process for the shellcode
    LPVOID pRemoteCode = VirtualAllocEx(hTargetProc, nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteCode) {
        std::cerr << "Failed to allocate memory for shellcode in target process." << std::endl;
        VirtualFreeEx(hTargetProc, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hTargetProc);
        return;
    }

    // Write the shellcode to the target process
    if (!WriteProcessMemory(hTargetProc, pRemoteCode, shellcode, sizeof(shellcode), nullptr)) {
        std::cerr << "Failed to write shellcode to target process." << std::endl;
        VirtualFreeEx(hTargetProc, pRemoteMemory, 0, MEM_RELEASE);
        VirtualFreeEx(hTargetProc, pRemoteCode, 0, MEM_RELEASE);
        CloseHandle(hTargetProc);
        return;
    }

    HANDLE hRemoteThread = CreateRemoteThread(hTargetProc, nullptr, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, nullptr, 0, nullptr);
    if (!hRemoteThread) {
        std::cerr << "Failed to create remote thread." << std::endl;
        VirtualFreeEx(hTargetProc, pRemoteMemory, 0, MEM_RELEASE);
        VirtualFreeEx(hTargetProc, pRemoteCode, 0, MEM_RELEASE);
        CloseHandle(hTargetProc);
        return;
    }
    WaitForSingleObject(hRemoteThread, INFINITE);
    int returnValue = 0;
    if (!ReadProcessMemory(hTargetProc, pRemoteMemory, &returnValue, sizeof(returnValue), nullptr)) {
        std::cout << "Failed to read return value from target process." << std::endl;
    }
    else {
        std::cout << "Return value of the target function: " << returnValue << std::endl;
    }

    VirtualFreeEx(hTargetProc, pRemoteMemory, 0, MEM_RELEASE);
    VirtualFreeEx(hTargetProc, pRemoteCode, 0, MEM_RELEASE);
    CloseHandle(hRemoteThread);
    CloseHandle(hTargetProc);
}


int main() {
    LPCWSTR targetProcess = L"Project1.exe";
    int PID = get_process_id(targetProcess);

    while (PID == 0) {
        PID = get_process_id(targetProcess);
        printf("Waiting For Targeted Process\n");
    }

    HANDLE hTargetProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (hTargetProc == NULL) {
        std::cerr << "Failed to open target process." << std::endl;
        return 1;
    }
    uintptr_t baseAddress = GetBaseAddressFromPID(PID);
    ////////////////////{Log_Start}////////////////////////
    std::cout << "[log] TargetApp => " << targetProcess << "\n";
    std::cout << "[log] Process_Id => " << PID << "\n";
    std::cout << "[log] Base_Address => " << baseAddress << "\n";
    ////////////////////{Log_End}////////////////////////
    uintptr_t targetFunctionAddr = (uintptr_t)(baseAddress + 0x1110); //Addr of the func that return int
    Execute_Function(hTargetProc, targetFunctionAddr);
    return 0;
}
