#pragma once
#include"TinyVT.h"

//用于保存HOOK信息的双向链表
typedef struct _EptHookInfo
{
	ULONG_PTR RealPagePhyAddr;

	ULONG_PTR FakePagePhyAddr;
	ULONG_PTR FakePageVaAddr;

	ULONG_PTR OriginalFunAddr;
	ULONG_PTR OriginalFunHeadCode;

	LIST_ENTRY list;
} EptHookInfo, * PEptHookInfo;

// SSDT的结构
typedef struct _SYSTEM_SERVICE_TABLE {
	PLONG  		ServiceTableBase;
	PVOID  		ServiceCounterTableBase;
	ULONGLONG  	NumberOfServices;
	PVOID  		ParamTableBase;
} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;


extern PSYSTEM_SERVICE_TABLE SsdtAddr;

//获取SSDT
UINT64 GetSSDT();
//通过SSDT得到函数地址
UINT64 GetSsdtFunAddr(ULONG dwIndex);

//通过物理地址得到HOOK信息
PEptHookInfo GetHookInfoByPA(ULONG_PTR physAddr);
//通过函数虚拟地址得到HOOK信息
PEptHookInfo GetHookInfoByFunAddr(ULONG_PTR vaAddr);

PVOID EptHOOK(ULONG_PTR FunAddr, PVOID FakeAddr);
VOID EptUnHOOK(ULONG_PTR FunAddr);
VOID DestroyEptHook();