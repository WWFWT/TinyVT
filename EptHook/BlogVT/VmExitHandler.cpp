#include"HOOK.h"

union EptViolationQualification {
	ULONG64 all;
	struct {
		ULONG64 read_access : 1;                   //!< [0]
		ULONG64 write_access : 1;                  //!< [1]
		ULONG64 execute_access : 1;                //!< [2]
		ULONG64 ept_readable : 1;                  //!< [3]
		ULONG64 ept_writeable : 1;                 //!< [4]
		ULONG64 ept_executable : 1;                //!< [5]
		ULONG64 ept_executable_for_user_mode : 1;  //!< [6]
		ULONG64 valid_guest_linear_address : 1;    //!< [7]
		ULONG64 caused_by_translation : 1;         //!< [8]
		ULONG64 user_mode_linear_address : 1;      //!< [9]
		ULONG64 readable_writable_page : 1;        //!< [10]
		ULONG64 execute_disable_page : 1;          //!< [11]
		ULONG64 nmi_unblocking : 1;                //!< [12]
	} fields;
};
static_assert(sizeof(EptViolationQualification) == 8, "Size check");

#pragma warning(push)
#pragma warning(disable:4244)

//有些VmExit事件触发处理完成后，回到Guest时需要跳过触发VmExit的代码
//比如VmCall的时候，不跳过的话，回到Guest又继续触发VmCall
//跳过Guest当前执行的代码
void VmmAdjustGuestRip()
{
	ULONG instLen = 0;
	ULONG_PTR rip = 0;
	__vmx_vmread(GuestRip, &rip);
	//获取Guest当前执行指令的长度
	__vmx_vmread(VmExitInstructionLength, (SIZE_T*)&instLen);
	__vmx_vmwrite(GuestRip, (SIZE_T)(rip + instLen));
}

//退出VT，这里我是CV了其他项目的
void VmxPrepareOff(GpRegisters* pGuestRegisters)
{
	/*
	当发生VM退出时，处理器将IDT和GDT的Limit设置为ffff。
	这里把它改回正确的值
	*/
	ULONG_PTR gdt_limit = 0;
	__vmx_vmread(GuestGDTRLimit, &gdt_limit);

	ULONG_PTR gdt_base = 0;
	__vmx_vmread(GuestGDTRBase, &gdt_base);
	ULONG_PTR idt_limit = 0;
	__vmx_vmread(GuestIDTRLimit, &idt_limit);
	ULONG_PTR idt_base = 0;
	__vmx_vmread(GuestIDTRBase, &idt_base);

	Gdtr gdtr = { (USHORT)gdt_limit, gdt_base };
	Idtr idtr = { (USHORT)(idt_limit), idt_base };
	AsmWriteGDT(&gdtr);
	__lidt(&idtr);


	//跳过VmCall指令
	ULONG_PTR exit_instruction_length = 0;
	__vmx_vmread(VmExitInstructionLength, &exit_instruction_length);
	ULONG_PTR rip = 0;
	__vmx_vmread(GuestRip, &rip);
	ULONG_PTR return_address = rip + exit_instruction_length;

	// Since the flag register is overwritten after VMXOFF, we should manually
	// indicates that VMCALL was successful by clearing those flags.
	// See: CONVENTIONS
	FlagRegister rflags = { 0 };
	__vmx_vmread(GuestRflags, (SIZE_T*)&rflags);

	rflags.fields.cf = FALSE;
	rflags.fields.pf = FALSE;
	rflags.fields.af = FALSE;
	rflags.fields.zf = FALSE;
	rflags.fields.sf = FALSE;
	rflags.fields.of = FALSE;
	rflags.fields.cf = FALSE;
	rflags.fields.zf = FALSE;

	// Set registers used after VMXOFF to recover the context. Volatile
	// registers must be used because those changes are reflected to the
	// guest's context after VMXOFF.
	pGuestRegisters->cx = return_address;
	__vmx_vmread(GuestRsp, &pGuestRegisters->dx);
	pGuestRegisters->ax = rflags.all;
}

//处理MSR的读写，不用理，CV即可
VOID ReadWriteMsrHandle(GpRegisters* pGuestRegisters, BOOLEAN isRead)
{
	MSR msr = (MSR)__readmsr(pGuestRegisters->cx);

	BOOLEAN transfer_to_vmcs = false;
	VmcsField vmcs_field = {};
	switch (msr) {
	case MSR::MsrSysenterCs:
		vmcs_field = VmcsField::GuestIa32SYSENTERCS;
		transfer_to_vmcs = true;
		break;
	case MSR::MsrSysenterEsp:
		vmcs_field = VmcsField::GuestIa32SYSENTERESP;
		transfer_to_vmcs = true;
		break;
	case MSR::MsrSysenterEip:
		vmcs_field = VmcsField::GuestIa32SYSENTEREIP;
		transfer_to_vmcs = true;
		break;
	case MSR::MsrDebugctl:
		vmcs_field = VmcsField::GuestIa32DebugCtl;
		transfer_to_vmcs = true;
		break;
	case MSR::MsrGsBase:
		vmcs_field = VmcsField::GuestGsBase;
		transfer_to_vmcs = true;
		break;
	case MSR::MsrFsBase:
		vmcs_field = VmcsField::GuestFsBase;
		transfer_to_vmcs = true;
		break;
	default:
		break;
	}

	LARGE_INTEGER msr_value = {};
	if (isRead) {
		if (transfer_to_vmcs) {
			__vmx_vmread(vmcs_field, (SIZE_T*)&msr_value.QuadPart);
		}
		else {
			__vmx_vmread(msr, (SIZE_T*)&msr_value.QuadPart);
		}

		pGuestRegisters->ax = msr_value.LowPart;
		pGuestRegisters->dx = msr_value.HighPart;
	}
	else
	{
		msr_value.LowPart = (ULONG)pGuestRegisters->ax;
		msr_value.HighPart = (ULONG)pGuestRegisters->dx;
		if (transfer_to_vmcs) {
			__vmx_vmwrite(vmcs_field, (ULONG_PTR)msr_value.QuadPart);
		}
		else {
			__vmx_vmwrite(msr, (ULONG_PTR)msr_value.QuadPart);
		}
	}
}


VOID EptViolationHandle()
{
	//获取触发EptViolation的地址
	ULONG_PTR ExitPhyAddr = 0;
	__vmx_vmread(VmExitGuestPhysicalAddress, &ExitPhyAddr);

	//通过触发EptViolation的地址，查找是不是跟我们HOOK有关
	PEptHookInfo hookInfo = GetHookInfoByPA(ExitPhyAddr);

	if (hookInfo)
	{
		EptCommonEntry* pte = GetPteByPhyAddr(ExitPhyAddr);

		//如果触发EptViolation时，当前页是能执行，而这里只有两种情况，要么能执行不能读写，要么能读写不能执行
		//能执行说明它是读或写只能执行的页面而触发了EptViolation，让它读写原函数页
		if (pte->fields.execute_access) {
			pte->fields.execute_access = 0;
			pte->fields.read_access = 1;
			pte->fields.write_access = 1;
			pte->fields.physial_address = hookInfo->RealPagePhyAddr >> 12;
		}
		else {
			//如果触发EptViolation时，当前页是可读可写，说明它是执行触发了EptViolation，让它执行HOOK函数页
			pte->fields.execute_access = 1;
			pte->fields.read_access = 0;
			pte->fields.write_access = 0;
			pte->fields.physial_address = hookInfo->FakePagePhyAddr >> 12;
		}
	}
	else {
		DbgBreakPoint();
	}
}


BOOLEAN VmCallHandle(GpRegisters* pGuestRegisters)
{
	//x64下都是fastcall调用约定
	//VmCall的功能号
	ULONG_PTR num = pGuestRegisters->cx;
	//附加的参数
	ULONG_PTR param = pGuestRegisters->dx;

	BOOLEAN ContinueVmx = TRUE;

	EptCommonEntry* pte = 0;
	PEptHookInfo hookInfo = 0;

	switch (num)
	{
	case CallExitVT:
		ContinueVmx = FALSE;
		VmxPrepareOff(pGuestRegisters);
		break;
	case CallEptHook:
		//HOOK的时候，把原函数所在页改成复制出来的页面，并且只能执行
		hookInfo = (PEptHookInfo)param;
		pte = GetPteByPhyAddr(hookInfo->RealPagePhyAddr);
		if (pte) {
			pte->fields.physial_address = hookInfo->FakePagePhyAddr >> 12;
			pte->fields.execute_access = 1;
			pte->fields.read_access = 0;
			pte->fields.write_access = 0;
		}
		break;
	case CallEptUnHook:
		//HOOK的时候，把原函数所在页改回去，并且赋予全部权限
		hookInfo = (PEptHookInfo)param;
		pte = GetPteByPhyAddr(hookInfo->RealPagePhyAddr);
		if (pte) {
			pte->fields.physial_address = hookInfo->RealPagePhyAddr >> 12;
			pte->fields.execute_access = 1;
			pte->fields.read_access = 1;
			pte->fields.write_access = 1;
		}
		break;
	default:
		Log("未知的VmCall");
		break;
	}

	return ContinueVmx;
}


EXTERN_C BOOLEAN VmexitHandler(GpRegisters* pGuestRegisters)
{
	KIRQL irql = KeGetCurrentIrql();
	if (irql < DISPATCH_LEVEL) {
		KeRaiseIrqlToDpcLevel();
	}

	ULONG CurrentProcessorIndex = KeGetCurrentProcessorNumberEx(NULL);
	VmExitInformation ExitReason = { 0 };
	FlagRegister guestRflag = { 0 };
	BOOLEAN ContinueVmx = TRUE;
	ULONG_PTR Rip = 0;

	__vmx_vmread(GuestRip, &Rip);
	__vmx_vmread(VmExitReason, (SIZE_T*)(&ExitReason));


	switch (ExitReason.fields.reason)
	{
	case ExitTripleFault:
		Log("TripleFault %p", Rip);
		//VmmAdjustGuestRip();
		DbgBreakPoint();
		break;
	case ExitEptMisconfig:
		Log("ExitEptMisconfig");
		DbgBreakPoint();
		break;
	case ExitEptViolation:
		EptViolationHandle();
		break;
	case ExitCrAccess:
		break;
		//msr读写必须处理
	case ExitMsrRead:
	{
		Log("ExitMsrRead %p", Rip);
		ReadWriteMsrHandle(pGuestRegisters, TRUE);
		VmmAdjustGuestRip();
		break;
	}
	case ExitMsrWrite:
	{
		Log("ExitMsrWrite");
		ReadWriteMsrHandle(pGuestRegisters, FALSE);
		VmmAdjustGuestRip();
		break;
	}
	case ExitCpuid:
	{
		//Log("ExitCpuid");
		//访问很频繁
		int leaf = (int)pGuestRegisters->ax;
		int sub_leaf = (int)pGuestRegisters->cx;
		int result[4] = { 0 };
		__cpuidex((int*)&result, leaf, sub_leaf);

		//if (leaf ==1)
		//{
		//	//((CpuFeaturesEcx*)&result[2])->fields.
		//}
		pGuestRegisters->ax = result[0];
		pGuestRegisters->bx = result[1];
		pGuestRegisters->cx = result[2];
		pGuestRegisters->dx = result[3];
		VmmAdjustGuestRip();
		break;
	}
	case ExitIoInstruction:
	{
		Log("ExitIoInstruction");
		VmmAdjustGuestRip();
		break;
	}
	case ExitVmcall:
	{
		ContinueVmx = VmCallHandle(pGuestRegisters);
		//如果不是退出VT，跳过VmCall指令继续执行
		if (ContinueVmx) VmmAdjustGuestRip();
		break;
	}
	case ExitExceptionOrNmi:
	{
		Log("ExitExceptionOrNmi");
		VmExitInterruptionInformationField exception = { 0 };
		__vmx_vmread(VmExitInterruptionInformation, (SIZE_T*)&exception);

		if (exception.fields.interruption_type == kHardwareException)
		{
			//VmmpInjectInterruption(exception.fields.interruption_type,)
			exception.fields.valid = TRUE;
			__vmx_vmwrite(VmEntryInterruptionInformation, exception.all);
		}
		else if (exception.fields.interruption_type == kSoftwareException)
		{
			__vmx_vmwrite(VmEntryInterruptionInformation, exception.all);
			int exit_inst_length = 0;
			__vmx_vmread(VmExitInstructionLength, (SIZE_T*)&exit_inst_length);
			__vmx_vmwrite(VmEntryInstructionLength, exit_inst_length);
		}
		break;
	}
	case ExitMonitorTrapFlag:
	{
		Log("ExitMonitorTrapFlag");

		break;
	}
	case ExitHlt:
	{
		Log("ExitHlt");
		break;
	}
	case ExitVmclear:
	case ExitVmptrld:
	case ExitVmptrst:
	case ExitVmread:
	case ExitVmwrite:
	case ExitVmresume:
	case ExitVmoff:
	case ExitVmon:
	case ExitVmlaunch:
	case ExitVmfunc:
	case ExitInvept:
	case ExitInvvpid:
	{
		Log("vm inst %d", ExitReason.fields.reason);
		__vmx_vmread(GuestRflags, (SIZE_T*)&guestRflag);
		guestRflag.fields.cf = 1;
		__vmx_vmwrite(GuestRflags, guestRflag.all);
		VmmAdjustGuestRip();
		break;
	}
	case ExitInvd:
	{
		Log("ExitInvd");
		AsmInvd();
		VmmAdjustGuestRip();
		break;
	}
	case ExitInvlpg:
	{
		Log("ExitInvlpg");
		ExitQualification eq = { 0 };
		__vmx_vmread(VmExitQualification, (SIZE_T*)&eq);
		InvVpidDescriptor desc = { 0 };
		desc.vpid = CurrentProcessorIndex + 1;
		desc.linear_address = eq.all;
		AsmInvvpid(kIndividualAddressInvalidation, (SIZE_T*)&desc);
		VmmAdjustGuestRip();
		break;
	}
	case ExitRdtsc:
	{
		Log("ExitRdtsc");

		ULARGE_INTEGER tsc = { 0 };
		tsc.QuadPart = __rdtsc();
		pGuestRegisters->dx = tsc.HighPart;
		pGuestRegisters->ax = tsc.LowPart;
		VmmAdjustGuestRip();
		break;
	}
	case ExitRdtscp:
	{
		Log("ExitRdtscp");

		unsigned int tsc_aux = 0;
		ULARGE_INTEGER tsc = { 0 };
		tsc.QuadPart = __rdtscp(&tsc_aux);
		pGuestRegisters->dx = tsc.HighPart;
		pGuestRegisters->ax = tsc.LowPart;
		pGuestRegisters->cx = tsc_aux;
		VmmAdjustGuestRip();
		break;
	}
	case ExitXsetbv:
	{
		Log("ExitXsetbv");

		ULARGE_INTEGER value = { 0 };
		value.LowPart = pGuestRegisters->ax;
		value.HighPart = pGuestRegisters->dx;
		_xsetbv(pGuestRegisters->cx, value.QuadPart);

		VmmAdjustGuestRip();
		break;
	}
	default:
		Log("Unexpected Exit %d", ExitReason.fields.reason);
		DbgBreakPoint();
		break;
	}

	if (irql < DISPATCH_LEVEL) {
		KeLowerIrql(irql);
	}

	return ContinueVmx;
}

#pragma warning(pop)