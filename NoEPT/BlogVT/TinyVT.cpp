#include"TinyVT.h"

TinyVT::TinyVT(int index)
{
	this->index = index;
	VMX_Region = (ULONG_PTR)kmalloc(PAGE_SIZE);
	VMCS_Region = (ULONG_PTR)kmalloc(PAGE_SIZE);
	MsrBitmap = (ULONG_PTR)kmalloc(PAGE_SIZE);
	VmmStack = (PCHAR)kmalloc(VMM_STACK_SIZE);
	Log("当前CPU:%d",index);
}

TinyVT::~TinyVT()
{
	Cr4 cr4 = { 0 };
	cr4.all = __readcr4();
	if (cr4.fields.vmxe)
	{
		cr4.fields.vmxe = 0;
		__writecr4(cr4.all);
	}

	kfree((PVOID)VMX_Region);
	kfree((PVOID)VMCS_Region);
	kfree((PVOID)MsrBitmap);
	kfree(VmmStack);

	Ia32FeatureControlMsr msr = { 0 };
	msr.all = __readmsr(MsrFeatureControl);
	if (msr.fields.lock)
	{
		msr.fields.lock = FALSE;
		msr.fields.enable_vmxon = FALSE;
		__writemsr(MsrFeatureControl, msr.all);
		msr.all = __readmsr(MsrFeatureControl);
	}
}

BOOLEAN TinyVT::StartVT()
{
	isEnable = ExecuteVMXON();
	if (!isEnable) {
		Log("[CPU;%d]VMXON失败！", index);
		return FALSE;
	}

	FunAddr funAddr = { 0 };
	funAddr.fun = &TinyVT::InitVMCS;

	isEnable = AsmVmxLaunch(funAddr.addr, this);

	return isEnable;
}

BOOLEAN TinyVT::ExecuteVMXON()
{
	//填充版本号
#pragma warning(push)
#pragma warning(disable:4244)
	*(ULONG*)VMX_Region = __readmsr(MsrVmxBasic);
	*(ULONG*)VMCS_Region = __readmsr(MsrVmxBasic);
#pragma warning(pop)

	//设置CR4
	Cr4 cr4 = { 0 };
	cr4.all = __readcr4();
	cr4.fields.vmxe = TRUE;
	__writecr4(cr4.all);

	//对每个cpu开启vmxon指令的限制
	Ia32FeatureControlMsr msr = { 0 };
	msr.all = __readmsr(MsrFeatureControl);
	if (!msr.fields.lock)
	{
		msr.fields.lock = TRUE;
		msr.fields.enable_vmxon = TRUE;
		__writemsr(MsrFeatureControl, msr.all);
		msr.all = __readmsr(MsrFeatureControl);
	}

	//执行VMXON
	ULONG_PTR phyaddr = MmGetPhysicalAddress((PVOID)VMX_Region).QuadPart;
	__vmx_on(&phyaddr);

	FlagRegister eflags = { 0 };

	*(ULONG_PTR*)(&eflags) = __readeflags();
	if (eflags.fields.cf != 0) {
		Log("[CPU:%d]VMXON执行失败！",index);
		return FALSE;
	}

	phyaddr = MmGetPhysicalAddress((PVOID)VMCS_Region).QuadPart;
	//初始化VMCS区域
	__vmx_vmclear(&phyaddr);
	//选中当前VMCS区域，为填充VMCS区域作准备
	__vmx_vmptrld(&phyaddr);
	return TRUE;
}
