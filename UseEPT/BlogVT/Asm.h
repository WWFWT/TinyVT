#pragma once
#include"def.h"

enum VmCall
{
	CallExitVT,
	CallEptHook,
	CallEptUnHook,
};

EXTERN_C
{
BOOLEAN __fastcall AsmVmxLaunch(PVOID callBack,PVOID thisPoint);
void __fastcall AsmVmmEntryPoint();
void __fastcall AsmInvd();
void __fastcall AsmVmxCall(ULONG_PTR num, ULONG_PTR param);

unsigned char __fastcall __fastcall AsmInvvpid(
	_In_ ULONG_PTR invvpid_type,
	_In_ ULONG_PTR* invvpid_descriptor);


void _sgdt(void*);
/// Writes to GDT
/// @param gdtr   A value to write
void __fastcall AsmWriteGDT(_In_ const Gdtr* gdtr);

/// Reads SLDT
/// @return LDT
USHORT __fastcall AsmReadLDTR();

/// Writes to TR
/// @param task_register   A value to write
void __fastcall AsmWriteTR(_In_ USHORT task_register);

/// Reads STR
/// @return TR
USHORT __fastcall AsmReadTR();

/// Writes to ES
/// @param segment_selector   A value to write
void __fastcall AsmWriteES(_In_ USHORT segment_selector);

/// Reads ES
/// @return ES
USHORT __fastcall AsmReadES();

/// Writes to CS
/// @param segment_selector   A value to write
void __fastcall AsmWriteCS(_In_ USHORT segment_selector);

/// Reads CS
/// @return CS
USHORT __fastcall AsmReadCS();

/// Writes to SS
/// @param segment_selector   A value to write
void __fastcall AsmWriteSS(_In_ USHORT segment_selector);

/// Reads SS
/// @return SS
USHORT __fastcall AsmReadSS();

/// Writes to DS
/// @param segment_selector   A value to write
void __fastcall AsmWriteDS(_In_ USHORT segment_selector);

/// Reads DS
/// @return DS
USHORT __fastcall AsmReadDS();

/// Writes to FS
/// @param segment_selector   A value to write
void __fastcall AsmWriteFS(_In_ USHORT segment_selector);

/// Reads FS
/// @return FS
USHORT __fastcall AsmReadFS();

/// Writes to GS
/// @param segment_selector   A value to write
void __fastcall AsmWriteGS(_In_ USHORT segment_selector);

/// Reads GS
/// @return GS
USHORT __fastcall AsmReadGS();

/// Loads access rights byte
/// @param segment_selector   A value to get access rights byte
/// @return An access rights byte
ULONG_PTR __fastcall AsmLoadAccessRightsByte(_In_ ULONG_PTR segment_selector);

}
