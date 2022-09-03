#include"TinyVT.h"
#include"HOOK.h"
#include<Ndis.h>

TinyVT* AllVT[128] = {0};

EXTERN_C VOID LoadVT(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);

	//获取当前CPU核心的号数
	ULONG index = KeGetCurrentProcessorIndex();
	if (CheckVTSupport() && CheckVTEnable())
	{
		TinyVT* tinyVt = new TinyVT(index);
		if (tinyVt->StartVT()) {
			AllVT[index] = tinyVt;
			Log("[CPU:%d]启动VT成功", index);
		}
		else {
			Log("[CPU:%d]启动VT失败",index);
		}
		
	}
	else {
		Log("[CPU:%d]不支持虚拟化", index);
	}

	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}

EXTERN_C VOID UnloadVT(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);

	int index = KeGetCurrentProcessorIndex();

	if (AllVT[index] && AllVT[index]->isEnable) {
		AsmVmxCall(CallExitVT, NULL);
	}

	if (AllVT[index]) {
		delete AllVT[index];
		AllVT[index] = NULL;
	}
	Log("[CPU:%d]VT已退出", index);

	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}


EXTERN_C VOID DriverUnload(PDRIVER_OBJECT driver)
{
	UNREFERENCED_PARAMETER(driver);

	//先销毁HOOK再退VT
	//DestroyEptHook();
	//延时等一下销毁完毕
	NdisStallExecution(50);

	KeGenericCallDpc(UnloadVT, NULL);

	//延时等一下VT退出完毕
	NdisStallExecution(50);
	if (EptMem) {
		kfree(EptMem);
		EptMem = 0;
	}

	Log("驱动卸载");
}

EXTERN_C VOID HookTest();

//已C语言方式导出，C++为支持函数重载，函数名会被改变，导致编译不通过
EXTERN_C VOID DriverEntry(PDRIVER_OBJECT driver, UNICODE_STRING path)
{
	//用不到的参数用UNREFERENCED_PARAMETER括起来，否则报错，也在属性->C/C++ ->“警告视为错误”关掉，这里及之后的文章里都不关
	UNREFERENCED_PARAMETER(path);
	driver->DriverUnload = DriverUnload;

	if (!InitEpt()) {
		UseEpt = FALSE;
		Log("Ept初始化失败!");
	}

	KeGenericCallDpc(LoadVT, NULL);

	//等一下所有核心加载完VT
	NdisStallExecution(50);
	//HookTest();
	
	Log("驱动加载");
}