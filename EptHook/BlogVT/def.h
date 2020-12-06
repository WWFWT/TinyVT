#pragma once
#include<ntifs.h>
#include<intrin.h>
#include"ia32.h"

#define Log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL,"[MyVT]: " format "\n",##__VA_ARGS__)

EXTERN_C
NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
KeSignalCallDpcDone(
	_In_ PVOID SystemArgument1
);

EXTERN_C
NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
LOGICAL
KeSignalCallDpcSynchronize(
	_In_ PVOID SystemArgument2
);

EXTERN_C
NTKERNELAPI
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KeGenericCallDpc(
	_In_ PKDEFERRED_ROUTINE Routine,
	_In_opt_ PVOID Context
);

_IRQL_requires_max_(DISPATCH_LEVEL)
void* __cdecl operator new(size_t size);

_IRQL_requires_max_(DISPATCH_LEVEL)
void __cdecl operator delete(void* p, SIZE_T size);

BOOLEAN CheckVTSupport();
BOOLEAN CheckVTEnable();
PVOID kmalloc(ULONG_PTR size);
void kfree(PVOID p);