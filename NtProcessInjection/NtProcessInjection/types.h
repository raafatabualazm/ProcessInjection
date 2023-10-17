#include <Windows.h>

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;



typedef __kernel_entry NTSYSCALLAPI NTSTATUS(NTAPI* NtOpenProcess)(
		PHANDLE            ProcessHandle,
		ACCESS_MASK        DesiredAccess,
		POBJECT_ATTRIBUTES   ObjectAttributes,
		PCLIENT_ID         ClientId
);

typedef __kernel_entry NTSYSCALLAPI NTSTATUS(NTAPI* NtAllocateVirtualMemory)(
	    HANDLE    ProcessHandle,
		PVOID* BaseAddress,
	    ULONG_PTR ZeroBits,
		PSIZE_T   RegionSize,
	    ULONG     AllocationType,
	    ULONG     Protect
);

typedef __kernel_entry NTSYSCALLAPI NTSTATUS(NTAPI* NtWriteVirtualMemory)(



	HANDLE               ProcessHandle,
	PVOID                BaseAddress,
	PVOID                Buffer,
	ULONG                NumberOfBytesToWrite,
	PULONG              NumberOfBytesWritten
);

typedef  __kernel_entry NTSYSCALLAPI NTSTATUS(NTAPI* NtCreateThreadEx)(
	PHANDLE hThread,
	ACCESS_MASK DesiredAccess,
	PVOID ObjectAttributes,
	HANDLE ProcessHandle,
	PVOID lpStartAddress,
	PVOID lpParameter,
	ULONG Flags,
	SIZE_T StackZeroBits,
	SIZE_T SizeOfStackCommit,
	SIZE_T SizeOfStackReserve,
	PVOID lpBytesBuffer
);