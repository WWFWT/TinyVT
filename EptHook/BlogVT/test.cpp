#include"HOOK.h"

typedef NTSTATUS(*pNtOpenProcess)(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
	);


pNtOpenProcess OriginalNtOpenProcess = NULL;
int index = 0;

//代理函数
NTSTATUS MyNtOpenProcess(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
)
{
	if ((index % 100) == 0) {
		Log("HOOK NtOpenProcess 调用次数: %d", index);
	}
	index++;
	return OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

//测试HOOK NtOpenProcess
//EptHOOK(原函数地址, 代理函数地址)
EXTERN_C VOID HookTest()
{
	OriginalNtOpenProcess = (pNtOpenProcess)EptHOOK(GetSsdtFunAddr(38), MyNtOpenProcess);
}
