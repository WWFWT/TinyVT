#include"def.h"

BOOLEAN CheckVTSupport()
{
	int ctx[4] = { 0 };

	//获取CPU信息，如果成功,ctx中分别会存放eax到edx的信息
	__cpuidex(ctx, 1, 0);

	//检查ecx的第五位是否为0,0表示该CPU不支持VT,IA32手册卷3C 23.6
	if ((ctx[2] & (1 << 5)) == 0)
	{
		//不支持虚拟化
		return FALSE;
	}

	return TRUE;
}

BOOLEAN CheckVTEnable()
{
	ULONG_PTR msr;
	msr = __readmsr(0x3A);

	//检查第0位是否为0,也就是BIOS中VT是否开启,0是关闭(见IA32手册卷3C 23.7,因为Windows系统本身就是在保护模式下,所以不需要检查CR0了)
	if ((msr & 1) == 0)
		return FALSE;

	return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void* __cdecl operator new(size_t size) {
	if (size == 0) {
		size = 1;
	}
	PVOID ptr = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'vt');
	if (ptr == NULL) {
		Log("new操作分配内存失败！");
	}
	return ptr;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void __cdecl operator delete(void* p, SIZE_T size) {
	UNREFERENCED_PARAMETER(size);
	if (p) {
		ExFreePoolWithTag(p, 'vt');
	}
}

PVOID kmalloc(ULONG_PTR size)
{
	PHYSICAL_ADDRESS MaxAddr = { 0 };
	MaxAddr.QuadPart = -1;
	PVOID addr = MmAllocateContiguousMemory(size, MaxAddr);
	if (addr)
		RtlSecureZeroMemory(addr, size);
	else
		Log("分配内存失败");
	return addr;
}

void kfree(PVOID p)
{
	if (p) MmFreeContiguousMemory((PVOID)p);
}