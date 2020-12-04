#include"TinyVT.h"

SegmentDescriptor* VmpGetSegmentDescriptor(ULONG_PTR descriptor_table_base, USHORT segment_selector) {

	const SegmentSelector ss = { segment_selector };
	return (SegmentDescriptor*)(
		descriptor_table_base + ss.fields.index * sizeof(SegmentDescriptor));
}


ULONG_PTR VmpGetSegmentBaseByDescriptor(const SegmentDescriptor* segment_descriptor) {

	// Calculate a 32bit base address
	const ULONG_PTR base_high = { segment_descriptor->fields.base_high << (6 * 4) };
	const ULONG_PTR base_middle = { segment_descriptor->fields.base_mid << (4 * 4) };
	const ULONG_PTR base_low = { segment_descriptor->fields.base_low };

	ULONG_PTR base = (base_high | base_middle | base_low) & MAXULONG;
	// Get upper 32bit of the base address if needed
	if (!segment_descriptor->fields.system) {
		SegmentDesctiptorX64* desc64 = (SegmentDesctiptorX64*)(segment_descriptor);
		ULONG64 base_upper32 = desc64->base_upper32;
		base |= (base_upper32 << 32);
	}
	return base;
}


ULONG_PTR VmpGetSegmentBase(
	ULONG_PTR gdt_base, USHORT segment_selector) {

	SegmentSelector ss = { segment_selector };
	if (!ss.all) {
		return 0;
	}

	if (ss.fields.ti) {
		SegmentDescriptor* local_segment_descriptor =
			VmpGetSegmentDescriptor(gdt_base, AsmReadLDTR());
		ULONG_PTR  ldt_base =
			VmpGetSegmentBaseByDescriptor(local_segment_descriptor);


		SegmentDescriptor* segment_descriptor =
			VmpGetSegmentDescriptor(ldt_base, segment_selector);
		return VmpGetSegmentBaseByDescriptor(segment_descriptor);
	}
	else {
		SegmentDescriptor* segment_descriptor =
			VmpGetSegmentDescriptor(gdt_base, segment_selector);
		return VmpGetSegmentBaseByDescriptor(segment_descriptor);
	}
}

ULONG VmxGetSegmentAccessRight(USHORT segment_selector) {

	VmxRegmentDescriptorAccessRight access_right = { 0 };
	if (segment_selector) {
		const SegmentSelector ss = { segment_selector };
		ULONG_PTR native_access_right = AsmLoadAccessRightsByte(ss.all);
		native_access_right >>= 8;
		access_right.all = (ULONG)(native_access_right);
		access_right.fields.reserved1 = 0;
		access_right.fields.reserved2 = 0;
		access_right.fields.unusable = FALSE;
	}
	else {
		access_right.fields.unusable = TRUE;
	}
	return access_right.all;
}

ULONG VmxAdjustControlValue(ULONG Msr, ULONG Ctl)
{
	LARGE_INTEGER MsrValue = { 0 };
	MsrValue.QuadPart = __readmsr(Msr);
	Ctl &= MsrValue.HighPart;     //前32位为0的位置表示那些必须设置位0
	Ctl |= MsrValue.LowPart;      //后32位为1的位置表示那些必须设置位1
	return Ctl;
}

BOOLEAN TinyVT::InitVMCS(PVOID guestStack, PVOID guestResumeRip)
{
	Ia32VmxBasicMsr vBMsr = { 0 };
	vBMsr.all = __readmsr(MsrVmxBasic);

	//配置基于pin的vm执行控制信息域
	VmxPinBasedControls vm_pinctl_requested = { 0 };
	VmxPinBasedControls vm_pinctl = {
		VmxAdjustControlValue((vBMsr.fields.vmx_capability_hint) ? MsrVmxTruePinbasedCtls: MsrVmxPinbasedCtls,
							  vm_pinctl_requested.all) };
	__vmx_vmwrite(PinBasedVmExecutionControls, vm_pinctl.all);



	//配置基于处理器的主vm执行控制信息域
	VmxProcessorBasedControls vm_procctl_requested = { 0 };
	//vm_procctl_requested.fields.cr3_load_exiting = TRUE;//拦截MOV to CR3
	//vm_procctl_requested.fields.cr3_store_exiting = TRUE;//拦截mov from cr3
	//vm_procctl_requested.fields.cr8_load_exiting = TRUE;//拦截mov to cr8
	//vm_procctl_requested.fields.cr8_store_exiting = TRUE;//拦截 mov from cr8
	//vm_procctl_requested.fields.mov_dr_exiting = TRUE; //拦截调试寄存器访问
	//vm_procctl_requested.fields.use_io_bitmaps = TRUE; //拦截io指令
	//vm_procctl_requested.fields.unconditional_io_exiting = TRUE;//无条件拦截io指令
	vm_procctl_requested.fields.use_msr_bitmaps = TRUE;  //拦截msr寄存器访问,必须设置,不然任何访msr的操作都会导致vmexit
	vm_procctl_requested.fields.activate_secondary_control = TRUE;
	VmxProcessorBasedControls vm_procctl = {
		VmxAdjustControlValue((vBMsr.fields.vmx_capability_hint) ? MsrVmxTrueProcBasedCtls
											  : MsrVmxProcBasedCtls,
							  vm_procctl_requested.all) };
	__vmx_vmwrite(PrimaryProcessorBasedVmExecutionControls, vm_procctl.all);



	//配置基于处理器的辅助vm执行控制信息域
	VmxSecondaryProcessorBasedControls vm_procctl2_requested = { 0 };

	//vm_procctl2_requested.fields.descriptor_table_exiting = TRUE;//拦截LGDT, LIDT, LLDT, LTR, SGDT, SIDT, SLDT, STR. 
	vm_procctl2_requested.fields.enable_rdtscp = TRUE;  // for Win10
	vm_procctl2_requested.fields.enable_invpcid = TRUE;        // for Win10
	vm_procctl2_requested.fields.enable_xsaves_xstors = TRUE;  // for Win10
	VmxSecondaryProcessorBasedControls vm_procctl2 = { VmxAdjustControlValue(
		MsrVmxProcBasedCtls2, vm_procctl2_requested.all) };

	__vmx_vmwrite(SecondaryProcessorBasedVmExecutionControls, vm_procctl2.all);



	//配置vm-entry控制域
	VmxVmEntryControls vm_entryctl_requested = { 0 };
	//vm_entryctl_requested.fields.load_debug_controls = TRUE;
	vm_entryctl_requested.fields.ia32e_mode_guest = TRUE; //64系统必须填
	VmxVmEntryControls vm_entryctl = { VmxAdjustControlValue(
		(vBMsr.fields.vmx_capability_hint) ? MsrVmxTrueEntryCtls : MsrVmxEntryCtls,
		vm_entryctl_requested.all) };

	__vmx_vmwrite(VmEntryControls, vm_entryctl.all);



	//配置vm-exit控制信息域
	VmxVmExitControls vm_exitctl_requested = { 0 };
	vm_exitctl_requested.fields.host_address_space_size = TRUE;//64系统必须填
	VmxVmExitControls vm_exitctl = { VmxAdjustControlValue(
		(vBMsr.fields.vmx_capability_hint) ? MsrVmxTrueExitCtls : MsrVmxExitCtls,
		vm_exitctl_requested.all) };
	__vmx_vmwrite(VmExitControls, vm_exitctl.all);



	//配置其它控制域
	Cr0 cr0_mask = { 0 };
	Cr0 cr0_shadow = { __readcr0() };

	Cr4 cr4_mask = { 0 };
	Cr4 cr4_shadow = { __readcr4() };
	//用于有条件拦截cr0,cr4的访问
	__vmx_vmwrite(Cr0GuestHostMask, cr0_mask.all);
	__vmx_vmwrite(Cr4GuestHostMask, cr4_mask.all);
	__vmx_vmwrite(Cr0ReadShadow, 0);// cr0_shadow.all);
	__vmx_vmwrite(Cr4ReadShadow, 0);// cr4_shadow.all);


	ULONG_PTR MsrBitmapPhyAddr = MmGetPhysicalAddress((PVOID)MsrBitmap).QuadPart;
	__vmx_vmwrite(MsrBitmap, MsrBitmapPhyAddr);

	ULONG_PTR exception_bitmap = 0;
	__vmx_vmwrite(ExceptionBitmap, exception_bitmap);


	//配置guest state,主要是寄存器域
	Gdtr gdtr = { 0 };
	_sgdt(&gdtr);

	Idtr idtr = { 0 };
	__sidt(&idtr);

	__vmx_vmwrite(GuestEsSelector, AsmReadES());
	__vmx_vmwrite(GuestCsSelector, AsmReadCS());
	__vmx_vmwrite(GuestSsSelector, AsmReadSS());
	__vmx_vmwrite(GuestDsSelector, AsmReadDS());
	__vmx_vmwrite(GuestFsSelector, AsmReadFS());
	__vmx_vmwrite(GuestGsSelector, AsmReadGS());
	__vmx_vmwrite(GuestLDTRSelector, AsmReadLDTR());
	__vmx_vmwrite(GuestTRSelector, AsmReadTR());

	__vmx_vmwrite(GuestVmcsLinkPointer, MAXULONG64);
	__vmx_vmwrite(GuestIa32DebugCtl, __readmsr(MsrDebugctl));

	__vmx_vmwrite(GuestEsLimit, GetSegmentLimit(AsmReadES()));
	__vmx_vmwrite(GuestCsLimit, GetSegmentLimit(AsmReadCS()));
	__vmx_vmwrite(GuestSsLimit, GetSegmentLimit(AsmReadSS()));
	__vmx_vmwrite(GuestDsLimit, GetSegmentLimit(AsmReadDS()));
	__vmx_vmwrite(GuestFsLimit, GetSegmentLimit(AsmReadFS()));
	__vmx_vmwrite(GuestGsLimit, GetSegmentLimit(AsmReadGS()));
	__vmx_vmwrite(GuestLDTRLimit, GetSegmentLimit(AsmReadLDTR()));
	__vmx_vmwrite(GuestTRLimit, GetSegmentLimit(AsmReadTR()));
	__vmx_vmwrite(GuestGDTRLimit, gdtr.limit);
	__vmx_vmwrite(GuestIDTRLimit, idtr.limit);

	__vmx_vmwrite(GuestEsAccessRight, VmxGetSegmentAccessRight(AsmReadES()));
	__vmx_vmwrite(GuestCsAccessRight, VmxGetSegmentAccessRight(AsmReadCS()));
	__vmx_vmwrite(GuestSsAccessRight, VmxGetSegmentAccessRight(AsmReadSS()));
	__vmx_vmwrite(GuestDsAccessRight, VmxGetSegmentAccessRight(AsmReadDS()));
	__vmx_vmwrite(GuestFsAccessRight, VmxGetSegmentAccessRight(AsmReadFS()));
	__vmx_vmwrite(GuestGsAccessRight, VmxGetSegmentAccessRight(AsmReadGS()));
	__vmx_vmwrite(GuestLDTRAccessRight, VmxGetSegmentAccessRight(AsmReadLDTR()));
	__vmx_vmwrite(GuestTRAccessRight, VmxGetSegmentAccessRight(AsmReadTR()));
	__vmx_vmwrite(GuestIa32SYSENTERCS, __readmsr(MsrSysenterCs));

	__vmx_vmwrite(GuestCr0, __readcr0());
	__vmx_vmwrite(GuestCr3, __readcr3());
	__vmx_vmwrite(GuestCr4, __readcr4());

	__vmx_vmwrite(GuestEsBase, 0);
	__vmx_vmwrite(GuestCsBase, 0);
	__vmx_vmwrite(GuestSsBase, 0);
	__vmx_vmwrite(GuestDsBase, 0);
#pragma warning(push)
#pragma warning(disable:4245)
	__vmx_vmwrite(GuestFsBase, __readmsr(MsrFsBase));
	__vmx_vmwrite(GuestGsBase, __readmsr(MsrGsBase));

	__vmx_vmwrite(GuestLDTRBase, VmpGetSegmentBase(gdtr.base, AsmReadLDTR()));
	__vmx_vmwrite(GuestTRBase, VmpGetSegmentBase(gdtr.base, AsmReadTR()));
	__vmx_vmwrite(GuestGDTRBase, gdtr.base);
	__vmx_vmwrite(GuestIDTRBase, idtr.base);
	__vmx_vmwrite(GuestDr7, __readdr(7));
	__vmx_vmwrite(GuestRsp, (SIZE_T)guestStack);
	__vmx_vmwrite(GuestRip, (SIZE_T)guestResumeRip);
	__vmx_vmwrite(GuestRflags, __readeflags());
	__vmx_vmwrite(GuestIa32SYSENTERESP, __readmsr(MsrSysenterEsp));
	__vmx_vmwrite(GuestIa32SYSENTEREIP, __readmsr(MsrSysenterEip));

	//配置host state
	__vmx_vmwrite(HostEsSelector, AsmReadES() & 0xf8);
	__vmx_vmwrite(HostCsSelector, AsmReadCS() & 0xf8);
	__vmx_vmwrite(HostSsSelector, AsmReadSS() & 0xf8);
	__vmx_vmwrite(HostDsSelector, AsmReadDS() & 0xf8);
	__vmx_vmwrite(HostFsSelector, AsmReadFS() & 0xf8);
	__vmx_vmwrite(HostGsSelector, AsmReadGS() & 0xf8);
	__vmx_vmwrite(HostTrSelector, AsmReadTR() & 0xf8);
	__vmx_vmwrite(HostIa32SYSENTERCS, __readmsr(MsrSysenterCs));
	__vmx_vmwrite(HostCr0, __readcr0());
	__vmx_vmwrite(HostCr3, __readcr3());
	__vmx_vmwrite(HostCr4, __readcr4());
	__vmx_vmwrite(HostFsBase, __readmsr(MsrFsBase));
	__vmx_vmwrite(HostGsBase, __readmsr(MsrGsBase));
#pragma warning(pop)
	__vmx_vmwrite(HostTrBase, VmpGetSegmentBase(gdtr.base, AsmReadTR()));
	__vmx_vmwrite(HostGDTRBase, gdtr.base);
	__vmx_vmwrite(HostIDTRBase, idtr.base);
	__vmx_vmwrite(HostIa32SYSENTERESP, __readmsr(MsrSysenterEsp));
	__vmx_vmwrite(HostIa32SYSENTEREIP, __readmsr(MsrSysenterEip));

	//执行vmlaunch进入host的时候的host运行的栈
	__vmx_vmwrite(HostRsp, (SIZE_T)(VmmStack + VMM_STACK_SIZE - 0x1000));
	//执行vmlaunch进入host，host从AsmVmmEntryPoint这个函数开始运行
	__vmx_vmwrite(HostRip, (SIZE_T)AsmVmmEntryPoint);

	__vmx_vmlaunch();

	//如果执行到这里,说明失败了
	ULONG_PTR errorCode = 0;
	__vmx_vmread(VmVMInstructionError, &errorCode);
	Log("VmLaunch失败!错误码: %d", errorCode);

	return FALSE;
}