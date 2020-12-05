#pragma once
#ifndef _IA32_H
#define _IA32_H
#include <ntddk.h>

enum MSR
{
	MsrApicBase = 0x01B,

	MsrFeatureControl = 0x03A,

	MsrSysenterCs = 0x174,
	MsrSysenterEsp = 0x175,
	MsrSysenterEip = 0x176,

	MsrDebugctl = 0x1D9,

	MsrMtrrCap = 0xFE,
	MsrMtrrDefType = 0x2FF,
	MsrMtrrPhysBaseN = 0x200,
	MsrMtrrPhysMaskN = 0x201,
	MsrMtrrFix64k00000 = 0x250,
	MsrMtrrFix16k80000 = 0x258,
	MsrMtrrFix16kA0000 = 0x259,
	MsrMtrrFix4kC0000 = 0x268,
	MsrMtrrFix4kC8000 = 0x269,
	MsrMtrrFix4kD0000 = 0x26A,
	MsrMtrrFix4kD8000 = 0x26B,
	MsrMtrrFix4kE0000 = 0x26C,
	MsrMtrrFix4kE8000 = 0x26D,
	MsrMtrrFix4kF0000 = 0x26E,
	MsrMtrrFix4kF8000 = 0x26F,

	MsrVmxBasic = 0x480,
	MsrVmxPinbasedCtls = 0x481,
	MsrVmxProcBasedCtls = 0x482,
	MsrVmxExitCtls = 0x483,
	MsrVmxEntryCtls = 0x484,
	MsrVmxMisc = 0x485,
	MsrVmxCr0Fixed0 = 0x486,
	MsrVmxCr0Fixed1 = 0x487,
	MsrVmxCr4Fixed0 = 0x488,
	MsrVmxCr4Fixed1 = 0x489,
	MsrVmxVmcsEnum = 0x48A,
	MsrVmxProcBasedCtls2 = 0x48B,
	MsrVmxEptVpidCap = 0x48C,
	MsrVmxTruePinbasedCtls = 0x48D,
	MsrVmxTrueProcBasedCtls = 0x48E,
	MsrVmxTrueExitCtls = 0x48F,
	MsrVmxTrueEntryCtls = 0x490,
	MsrVmxVmfunc = 0x491,

	MsrEfer = 0xC0000080,
	MsrStar = 0xC0000081,
	MsrLstar = 0xC0000082,

	MsrFmask = 0xC0000084,

	MsrFsBase = 0xC0000100,
	MsrGsBase = 0xC0000101,
	MsrKernelGsBase = 0xC0000102,
	MsrTscAux = 0xC0000103,

};

enum VmcsField
{


	//基于pin的vm执行控制信息域
	PinBasedVmExecutionControls = 0x4000,
	//基于处理器的主vm执行控制信息域
	PrimaryProcessorBasedVmExecutionControls = 0x4002,
	//基于处理器的辅助vm执行控制信息域
	SecondaryProcessorBasedVmExecutionControls = 0x401e,
	//其它控制域
	VirtualProcessorId = 0x00000000,
	PostedInterruptNotification = 0x00000002,
	EptpIndex = 0x00000004,

	ExceptionBitmap = 0x00004004,
	PageFaultErrorCodeMask = 0x00004006,
	PageFaultErrorCodeMatch = 0x00004008,
	Cr3TargetCount = 0x0000400a,
	TprThreshold = 0x0000401c,
	PleGap = 0x00004020,
	PleWindow = 0x00004022,
	IoBitmapA = 0x00002000,
	IoBitmapAHigh = 0x00002001,
	IoBitmapB = 0x00002002,
	IoBitmapBHigh = 0x00002003,
	MsrBitmap = 0x00002004,
	MsrBitmapHigh = 0x00002005,
	ExecutiveVmcsPointer = 0x0000200c,
	ExecutiveVmcsPointerHigh = 0x0000200d,
	PMLAddress = 0x200e,
	PMLAddressHigh = 0x200f,
	TscOffset = 0x00002010,
	TscOffsetHigh = 0x00002011,
	VirtualApicPageAddr = 0x00002012,
	VirtualApicPageAddrHigh = 0x00002013,
	ApicAccessAddr = 0x00002014,
	ApicAccessAddrHigh = 0x00002015,
	PostedInterrputDescriptorAddr=0x2016,
	PostedInterrputDescriptorAdddrHigh = 0x2017,
	VmFunctionControls=0x2018,
	VmFunctionControlsHigh = 0x2019,
	EptPointer = 0x0000201a,
	EptPointerHigh = 0x0000201b,
	EoiExitBitmap0 = 0x0000201c,
	EoiExitBitmap0High = 0x0000201d,
	EoiExitBitmap1 = 0x0000201e,
	EoiExitBitmap1High = 0x0000201f,
	EoiExitBitmap2 = 0x00002020,
	EoiExitBitmap2High = 0x00002021,
	EoiExitBitmap3 = 0x00002022,
	EoiExitBitmap3High = 0x00002023,
	EptpListAddress = 0x00002024,
	EptpListAddressHigh = 0x00002025,
	VmreadBitmapAddress = 0x00002026,
	VmreadBitmapAddressHigh = 0x00002027,
	VmwriteBitmapAddress = 0x00002028,
	VmwriteBitmapAddressHigh = 0x00002029,
	VirtualizationExceptionInfoAddress = 0x0000202a,
	VirtualizationExceptionInfoAddressHigh = 0x0000202b,
	XssExitingBitmap = 0x0000202c,
	XssExitingBitmapHigh = 0x0000202d,
	EnclsExitingBitmap = 0x0000202e,
	EnclsExitingBitmapHigh = 0x0000202f,
	TscMultiplier = 0x00002032,
	TscMultiplierHigh = 0x00002033,
	Cr0GuestHostMask = 0x00006000,
	Cr4GuestHostMask = 0x00006002,
	Cr0ReadShadow = 0x00006004,
	Cr4ReadShadow = 0x00006006,
	Cr3TargetValue0 = 0x00006008,
	Cr3TargetValue1 = 0x0000600a,
	Cr3TargetValue2 = 0x0000600c,
	Cr3TargetValue3 = 0x0000600e,

	//vm-entry控制域
	VmEntryControls = 0x4012,
	VmEntryMsrLoadCount = 0x1014,
	VmEntryInterruptionInformation = 0x4016,
	VmEntryExceptionErrorCode = 0x4018,
	VmEntryInstructionLength = 0x401a,
	VmEntryMsrLoadAddress = 0x200a,
	VmEntryMsrLoadAddressHigh = 0x200b,

	//vm-exit控制信息域 
	VmExitControls = 0x400c,
	VmExitMsrStoreCount = 0x400e,
	VmExitMsrLoadCount = 0x4010,
	VmExitMsrStoreAddress = 0x2006,
	VmExitMsrStoreAddressHigh = 0x2007,
	VmExitMsrLoadAddress = 0x2008,
	VmExitMsrLoadAddressHigh = 0x2009,

	//vm-exit信息域 共16个
	VmExitReason = 0x4402,
	VmExitQualification = 0x6400,
	VmExitGuestLinearAddress = 0x640a,
	VmExitGuestPhysicalAddress = 0x2400,
	VmExitGuestPhysicalAddressHigh = 0x2401,
	VmExitInterruptionInformation = 0x4404,
	VmExitInterruptionErrorCode = 0x4406,
	VmExitIDTVectoringInformation = 0x4408,
	VmExitIDTVectoringErrorCode = 0x440a,
	VmExitInstructionLength = 0x440c,
	VmExitInstructionInformation = 0x440e,
	VmExitIORcx = 0x6402,
	VmExitIORsi = 0x6404,
	VmExitIORdi = 0x6406,
	VmExitIORip = 0x6408,
	VmVMInstructionError = 0x4400,

	//host state 共26个
	HostCr0 = 0x6c00,
	HostCr3 = 0x6c02,
	HostCr4 = 0x6c04,
	HostRsp = 0x6c14,
	HostRip = 0x6c16,
	HostEsSelector = 0xc00,
	HostCsSelector = 0xc02,
	HostSsSelector = 0xc04,
	HostDsSelector = 0xc06,
	HostFsSelector = 0xc08,
	HostGsSelector = 0xc0a,
	HostTrSelector = 0xc0c,

	HostFsBase = 0x6c06,
	HostGsBase = 0x6c08,
	HostTrBase = 0x6c0a,

	HostGDTRBase = 0x6c0c,
	HostIDTRBase = 0x6c0e,

	HostIa32SYSENTERCS = 0x4c00,
	HostIa32SYSENTERESP = 0x6c10,
	HostIa32SYSENTEREIP = 0x6c12,

	HostIa32PerfGlobalCtl = 0x2c04,
	HostIa32PerfGlobalCtlHigh = 0x2c05,
	HostIa32PatCtl = 0x2c00,
	HostIa32PatCtlHigh = 0x2c01,
	HostIa32EferCtl = 0x2c02,
	HostIa32EferCtlHigh = 0x2c03,


	//guest state
	GuestCr0 = 0x6800,
	GuestCr3 = 0x6802,
	GuestCr4 = 0x6804,
	GuestDr7 = 0x681a,
	GuestRsp = 0x681c,
	GuestRip = 0x681E,
	GuestRflags = 0x6820,

	GuestEsSelector = 0x800,
	GuestEsBase = 0x6806,
	GuestEsLimit = 0x4800,
	GuestEsAccessRight = 0x4814,

	GuestCsSelector = 0x802,
	GuestCsBase = 0x6808,
	GuestCsLimit = 0x4802,
	GuestCsAccessRight = 0x4816,

	GuestSsSelector = 0x804,
	GuestSsBase = 0x680a,
	GuestSsLimit = 0x4804,
	GuestSsAccessRight = 0x4818,

	GuestDsSelector = 0x806,
	GuestDsBase = 0x680c,
	GuestDsLimit = 0x4806,
	GuestDsAccessRight = 0x481a,

	GuestFsSelector = 0x808,
	GuestFsBase = 0x680e,
	GuestFsLimit = 0x4808,
	GuestFsAccessRight = 0x481c,

	GuestGsSelector = 0x80a,
	GuestGsBase = 0x6810,
	GuestGsLimit = 0x480a,
	GuestGsAccessRight = 0x481e,

	GuestLDTRSelector = 0x80c,
	GuestLDTRBase = 0x6812,
	GuestLDTRLimit = 0x480c,
	GuestLDTRAccessRight = 0x4820,

	GuestTRSelector = 0x80e,
	GuestTRBase = 0x6814,
	GuestTRLimit = 0x480e,
	GuestTRAccessRight = 0x4822,

	GuestGDTRBase = 0x6816,
	GuestGDTRLimit = 0x4810,

	GuestIDTRBase = 0x6818,
	GuestIDTRLimit = 0x4812,

	GuestIa32DebugCtl = 0x2802,
	GuestIa32DebugCtlHigh = 0x2803,

	GuestIa32SYSENTERCS = 0x482a,
	GuestIa32SYSENTERESP = 0x6824,
	GuestIa32SYSENTEREIP = 0x4826,

	GuestIa32PerfGlobalCtl = 0x2808,
	GuestIa32PerfGlobalCtlHigh = 0x2809,
	GuestIa32PatCtl = 0x2804,
	GuestIa32PatCtlHigh = 0x2805,
	GuestIa32EferCtl = 0x2806,
	GuestIa32EferCtlHigh = 0x2807,
	GuestIa32BndCfgs = 0x2812,
	GuestIa32BndCfgsHigh = 0x2813,

	GuestSmBase = 0x4828,

	GuestActivityState = 0x4826,
	GuestInterruptState = 0x4824,
	GuestPendingDebugExceptions = 0x6822,
	GuestVmcsLinkPointer = 0x2800,
	GuestVmcsLinkPointerHigh = 0x2801,
	GuestVmxPreemptionTimerValue = 0x482e,
	GuestPdpte0 = 0x280a,
	GuestPdpte0High = 0x280b,
	GuestPdpte1 = 0x280c,
	GuestPdpte1High = 0x280d,
	GuestPdpte2 = 0x280e,
	GuestPdpte2High = 0x280f,
	GuestPdpte3 = 0x2810,
	GuestPdpte3High = 0x2811,
	GuestInterruptStatus = 0x810,
	GuestPMLindex = 0x812
};




/************************************************以下是ept,分页相关定义************************************************/

typedef struct _HardwarePte {
	ULONG64 valid : 1;               //!< [0]
	ULONG64 write : 1;               //!< [1]
	ULONG64 owner : 1;               //!< [2]
	ULONG64 write_through : 1;       //!< [3]     PWT
	ULONG64 cache_disable : 1;       //!< [4]     PCD
	ULONG64 accessed : 1;            //!< [5]
	ULONG64 dirty : 1;               //!< [6]
	ULONG64 large_page : 1;          //!< [7]     PAT
	ULONG64 global : 1;              //!< [8]
	ULONG64 copy_on_write : 1;       //!< [9]
	ULONG64 prototype : 1;           //!< [10]
	ULONG64 reserved0 : 1;           //!< [11]
	ULONG64 page_frame_number : 36;  //!< [12:47]
	ULONG64 reserved1 : 4;           //!< [48:51]
	ULONG64 software_ws_index : 11;  //!< [52:62]
	ULONG64 no_execute : 1;          //!< [63]
}HardwarePte;

typedef union _PdptrRegister {
	ULONG64 all;
	struct {
		ULONG64 present : 1;             //!< [0]
		ULONG64 reserved1 : 2;           //!< [1:2]
		ULONG64 write_through : 1;       //!< [3]
		ULONG64 cache_disable : 1;       //!< [4]
		ULONG64 reserved2 : 4;           //!< [5:8]
		ULONG64 ignored : 3;             //!< [9:11]
		ULONG64 page_directory_pa : 41;  //!< [12:52]
		ULONG64 reserved3 : 11;          //!< [53:63]
	} fields;
}PdptrRegister;


enum memory_type
{
	kUncacheable = 0,
	kWriteCombining = 1,
	kWriteThrough = 4,
	kWriteProtected = 5,
	kWriteBack = 6,
	kUncached = 7,
};





typedef union _EptPointer {
	ULONG64 all;
	struct {
		ULONG64 memory_type : 3;                      //!< [0:2]
		ULONG64 page_walk_length : 3;                 //!< [3:5]
		ULONG64 enable_accessed_and_dirty_flags : 1;  //!< [6]
		ULONG64 reserved1 : 5;                        //!< [7:11]
		ULONG64 pml4_address : 36;                    //!< [12:48-1]
		ULONG64 reserved2 : 16;                       //!< [48:63]
	} fields;
}Eptp;

typedef union _EptCommonEntry {
	ULONG64 all;
	struct {
		ULONG64 read_access : 1;       //!< [0]
		ULONG64 write_access : 1;      //!< [1]
		ULONG64 execute_access : 1;    //!< [2]
		ULONG64 memory_type : 3;       //!< [3:5]
		ULONG64 reserved1 : 6;         //!< [6:11]
		ULONG64 physial_address : 36;  //!< [12:48-1]
		ULONG64 reserved2 : 16;        //!< [48:63]
	} fields;
}EptCommonEntry;
static_assert(sizeof(EptCommonEntry) == 8, "Size check");

typedef struct _EptData {
	Eptp ept_pointer;
	EptCommonEntry *ept_pml4;

	EptCommonEntry **preallocated_entries;  // An array of pre-allocated entries
	volatile long preallocated_entries_count;  // # of used pre-allocated entries
}EptData;

typedef struct _InvEptDescriptor {
	Eptp ept_pointer;
	ULONG64 reserved1;
}InvEptDescriptor;

enum InvEptType {
	kSingleContextInvalidation = 1,
	kGlobalInvalidation = 2,
};

typedef struct _InvVpidDescriptor {
	USHORT vpid;
	USHORT reserved1;
	ULONG32 reserved2;
	ULONG64 linear_address;
}InvVpidDescriptor;
enum  InvVpidType
{
	kIndividualAddressInvalidation = 0,
	kSingleContextVpidInvalidation = 1,
	kAllContextInvalidation = 2,
	kSingleContextInvalidationExceptGlobal = 3,
};




/************************************************以下是cpuid指令相关定义************************************************/

typedef union _Cpuid80000008Eax {
	ULONG32 all;
	struct {
		ULONG32 physical_address_bits : 8;  //!< [0:7]
		ULONG32 linear_address_bits : 8;    //!< [8:15]
	} fields;
}Cpuid80000008Eax;


typedef union _CpuFeaturesEcx {
	ULONG32 all;
	struct {
		ULONG32 sse3 : 1;       //!< [0] Streaming SIMD Extensions 3 (SSE3)
		ULONG32 pclmulqdq : 1;  //!< [1] PCLMULQDQ
		ULONG32 dtes64 : 1;     //!< [2] 64-bit DS Area
		ULONG32 monitor : 1;    //!< [3] MONITOR/WAIT
		ULONG32 ds_cpl : 1;     //!< [4] CPL qualified Debug Store
		ULONG32 vmx : 1;        //!< [5] Virtual Machine Technology
		ULONG32 smx : 1;        //!< [6] Safer Mode Extensions
		ULONG32 est : 1;        //!< [7] Enhanced Intel Speedstep Technology
		ULONG32 tm2 : 1;        //!< [8] Thermal monitor 2
		ULONG32 ssse3 : 1;      //!< [9] Supplemental Streaming SIMD Extensions 3
		ULONG32 cid : 1;        //!< [10] L1 context ID
		ULONG32 sdbg : 1;       //!< [11] IA32_DEBUG_INTERFACE MSR
		ULONG32 fma : 1;        //!< [12] FMA extensions using YMM state
		ULONG32 cx16 : 1;       //!< [13] CMPXCHG16B
		ULONG32 xtpr : 1;       //!< [14] xTPR Update Control
		ULONG32 pdcm : 1;       //!< [15] Performance/Debug capability MSR
		ULONG32 reserved : 1;   //!< [16] Reserved
		ULONG32 pcid : 1;       //!< [17] Process-context identifiers
		ULONG32 dca : 1;        //!< [18] prefetch from a memory mapped device
		ULONG32 sse4_1 : 1;     //!< [19] SSE4.1
		ULONG32 sse4_2 : 1;     //!< [20] SSE4.2
		ULONG32 x2_apic : 1;    //!< [21] x2APIC feature
		ULONG32 movbe : 1;      //!< [22] MOVBE instruction
		ULONG32 popcnt : 1;     //!< [23] POPCNT instruction
		ULONG32 reserved3 : 1;  //!< [24] one-shot operation using a TSC deadline
		ULONG32 aes : 1;        //!< [25] AESNI instruction
		ULONG32 xsave : 1;      //!< [26] XSAVE/XRSTOR feature
		ULONG32 osxsave : 1;    //!< [27] enable XSETBV/XGETBV instructions
		ULONG32 avx : 1;        //!< [28] AVX instruction extensions
		ULONG32 f16c : 1;       //!< [29] 16-bit floating-point conversion
		ULONG32 rdrand : 1;     //!< [30] RDRAND instruction
		ULONG32 not_used : 1;   //!< [31] Always 0 (a.k.a. HypervisorPresent)
	} fields;
}CpuFeaturesEcx;

typedef union _CpuFeaturesEdx {
	ULONG32 all;
	struct {
		ULONG32 fpu : 1;        //!< [0] Floating Point Unit On-Chip
		ULONG32 vme : 1;        //!< [1] Virtual 8086 Mode Enhancements
		ULONG32 de : 1;         //!< [2] Debugging Extensions
		ULONG32 pse : 1;        //!< [3] Page Size Extension
		ULONG32 tsc : 1;        //!< [4] Time Stamp Counter
		ULONG32 msr : 1;        //!< [5] RDMSR and WRMSR Instructions
		ULONG32 mce : 1;        //!< [7] Machine Check Exception
		ULONG32 cx8 : 1;        //!< [8] Thermal monitor 2
		ULONG32 apic : 1;       //!< [9] APIC On-Chip
		ULONG32 reserved1 : 1;  //!< [10] Reserved
		ULONG32 sep : 1;        //!< [11] SYSENTER and SYSEXIT Instructions
		ULONG32 mtrr : 1;       //!< [12] Memory Type Range Registers
		ULONG32 pge : 1;        //!< [13] Page Global Bit
		ULONG32 mca : 1;        //!< [14] Machine Check Architecture
		ULONG32 cmov : 1;       //!< [15] Conditional Move Instructions
		ULONG32 pat : 1;        //!< [16] Page Attribute Table
		ULONG32 pse36 : 1;      //!< [17] 36-Bit Page Size Extension
		ULONG32 psn : 1;        //!< [18] Processor Serial Number
		ULONG32 clfsh : 1;      //!< [19] CLFLUSH Instruction
		ULONG32 reserved2 : 1;  //!< [20] Reserved
		ULONG32 ds : 1;         //!< [21] Debug Store
		ULONG32 acpi : 1;       //!< [22] TM and Software Controlled Clock
		ULONG32 mmx : 1;        //!< [23] Intel MMX Technology
		ULONG32 fxsr : 1;       //!< [24] FXSAVE and FXRSTOR Instructions
		ULONG32 sse : 1;        //!< [25] SSE
		ULONG32 sse2 : 1;       //!< [26] SSE2
		ULONG32 ss : 1;         //!< [27] Self Snoop
		ULONG32 htt : 1;        //!< [28] Max APIC IDs reserved field is Valid
		ULONG32 tm : 1;         //!< [29] Thermal Monitor
		ULONG32 reserved3 : 1;  //!< [30] Reserved
		ULONG32 pbe : 1;        //!< [31] Pending Break Enable
	} fields;
}CpuFeaturesEdx;


/************************************************以下是重要msr寄存器相关定义************************************************/



typedef union _Ia32FeatureControlMsr {
	unsigned __int64 all;
	struct {
		unsigned lock : 1;                  //!< [0]
		unsigned enable_smx : 1;            //!< [1]
		unsigned enable_vmxon : 1;          //!< [2]
		unsigned reserved1 : 5;             //!< [3:7]
		unsigned enable_local_senter : 7;   //!< [8:14]
		unsigned enable_global_senter : 1;  //!< [15]
		unsigned reserved2 : 16;            //!<
		unsigned reserved3 : 32;            //!< [16:63]
	} fields;
}Ia32FeatureControlMsr;


typedef union _Ia32VmxBasicMsr {
	unsigned __int64 all;
	struct {
		unsigned revision_identifier : 31;    //!< [0:30]
		unsigned reserved1 : 1;               //!< [31]
		unsigned region_size : 12;            //!< [32:43]
		unsigned region_clear : 1;            //!< [44]
		unsigned reserved2 : 3;               //!< [45:47]
		unsigned supported_ia64 : 1;          //!< [48]
		unsigned supported_dual_moniter : 1;  //!< [49]
		unsigned memory_type : 4;             //!< [50:53]
		unsigned vm_exit_report : 1;          //!< [54]
		unsigned vmx_capability_hint : 1;     //!< [55]
		unsigned reserved3 : 8;               //!< [56:63]
	} fields;
}Ia32VmxBasicMsr;


typedef union _Ia32VmxMiscMsr {
	unsigned __int64 all;
	struct {
		unsigned time_stamp : 5;                               //!< [0:4]
		unsigned reserved1 : 1;                                //!< [5]
		unsigned supported_activity_state_hlt : 1;             //!< [6]
		unsigned supported_activity_state_shutdown : 1;        //!< [7]
		unsigned supported_activity_state_wait_for_sipi : 1;   //!< [8]
		unsigned reserved2 : 6;                                //!< [9:14]
		unsigned supported_read_ia32_smbase_msr : 1;           //!< [15]
		unsigned supported_cr3_target_value_number : 8;        //!< [16:23]
		unsigned supported_cr3_target_value_number_clear : 1;  //!< [24]
		unsigned maximum_msrs_number : 3;                      //!< [25:27]
		unsigned suppoeted_change_ia32_smm_monitor_ctl : 1;    //!< [28]
		unsigned supported_vmwrite_vm_exit_information : 1;    //!< [29]
		unsigned reserved3 : 2;                                //!< [30:31]
		unsigned revision_identifier : 32;                     //!< [32:63]
	} fields;
}Ia32VmxMiscMsr;

typedef union _Ia32VmxVmcsEnumMsr {
	unsigned __int64 all;
	struct {
		unsigned reserved1 : 1;                        //!< [0]
		unsigned supported_highest_vmcs_encoding : 9;  //!< [1:9]
		unsigned reserved2 : 22;                       //!<
		unsigned reserved3 : 32;                       //!< [10:63]
	} fields;
}Ia32VmxVmcsEnumMsr;

/// See: VPID AND EPT CAPABILITIES
typedef union _Ia32VmxEptVpidCapMsr {
	unsigned __int64 all;
	struct {
		unsigned support_execute_only_pages : 1;                        //!< [0]
		unsigned reserved1 : 5;                                         //!< [1:5]
		unsigned support_page_walk_length4 : 1;                         //!< [6]
		unsigned reserved2 : 1;                                         //!< [7]
		unsigned support_uncacheble_memory_type : 1;                    //!< [8]
		unsigned reserved3 : 5;                                         //!< [9:13]
		unsigned support_write_back_memory_type : 1;                    //!< [14]
		unsigned reserved4 : 1;                                         //!< [15]
		unsigned support_pde_2mb_pages : 1;                             //!< [16]
		unsigned support_pdpte_1_gb_pages : 1;                          //!< [17]
		unsigned reserved5 : 2;                                         //!< [18:19]
		unsigned support_invept : 1;                                    //!< [20]
		unsigned support_accessed_and_dirty_flag : 1;                   //!< [21]
		unsigned reserved6 : 3;                                         //!< [22:24]
		unsigned support_single_context_invept : 1;                     //!< [25]
		unsigned support_all_context_invept : 1;                        //!< [26]
		unsigned reserved7 : 5;                                         //!< [27:31]
		unsigned support_invvpid : 1;                                   //!< [32]
		unsigned reserved8 : 7;                                         //!< [33:39]
		unsigned support_individual_address_invvpid : 1;                //!< [40]
		unsigned support_single_context_invvpid : 1;                    //!< [41]
		unsigned support_all_context_invvpid : 1;                       //!< [42]
		unsigned support_single_context_retaining_globals_invvpid : 1;  //!< [43]
		unsigned reserved9 : 20;                                        //!< [44:63]
	} fields;
}Ia32VmxEptVpidCapMsr;


/// See: IA32_MTRRCAP Register
typedef union _Ia32MtrrCapabilitiesMsr {
	ULONG64 all;
	struct {
		ULONG64 variable_range_count : 8;   //!< [0:7]
		ULONG64 fixed_range_supported : 1;  //!< [8]
		ULONG64 reserved : 1;               //!< [9]
		ULONG64 write_combining : 1;        //!< [10]
		ULONG64 smrr : 1;                   //!< [11]
	} fields;
}Ia32MtrrCapabilitiesMsr;

/// See: IA32_MTRR_DEF_TYPE MSR
typedef union _Ia32MtrrDefaultTypeMsr {
	ULONG64 all;
	struct {
		ULONG64 default_mtemory_type : 8;  //!< [0:7]
		ULONG64 reserved : 2;              //!< [8:9]
		ULONG64 fixed_mtrrs_enabled : 1;   //!< [10]
		ULONG64 mtrrs_enabled : 1;         //!< [11]
	} fields;
}Ia32MtrrDefaultTypeMsr;

/// See: Fixed Range MTRRs
typedef union _Ia32MtrrFixedRangeMsr {
	ULONG64 all;
	struct {
		UCHAR types[8];
	} fields;
}Ia32MtrrFixedRangeMsr;

/// See: IA32_MTRR_PHYSBASEn and IA32_MTRR_PHYSMASKn Variable-Range Register
/// Pair
typedef union _Ia32MtrrPhysBaseMsr {
	ULONG64 all;
	struct {
		ULONG64 type : 8;        //!< [0:7]
		ULONG64 reserved : 4;    //!< [8:11]
		ULONG64 phys_base : 36;  //!< [12:MAXPHYADDR]
	} fields;
}Ia32MtrrPhysBaseMsr;

/// See: IA32_MTRR_PHYSBASEn and IA32_MTRR_PHYSMASKn Variable-Range Register
/// Pair
typedef union _Ia32MtrrPhysMaskMsr {
	ULONG64 all;
	struct {
		ULONG64 reserved : 11;   //!< [0:10]
		ULONG64 valid : 1;       //!< [11]
		ULONG64 phys_mask : 36;  //!< [12:MAXPHYADDR]
	} fields;
}Ia32MtrrPhysMaskMsr;

/// See: IA32_APIC_BASE MSR Supporting x2APIC
typedef union _Ia32ApicBaseMsr {
	ULONG64 all;
	struct {
		ULONG64 reserved1 : 8;            //!< [0:7]
		ULONG64 bootstrap_processor : 1;  //!< [8]
		ULONG64 reserved2 : 1;            //!< [9]
		ULONG64 enable_x2apic_mode : 1;   //!< [10]
		ULONG64 enable_xapic_global : 1;  //!< [11]
		ULONG64 apic_base : 24;           //!< [12:35]
	} fields;
}Ia32ApicBaseMsr;

/************************************************以下是分段相关定义************************************************/

#include <pshpack1.h>
typedef struct _Idtr {
	unsigned short limit;
	ULONG_PTR base;
}Idtr;

typedef struct _Gdtr {
	unsigned short limit;
	ULONG_PTR base;
}Gdtr;




typedef struct _KidtEntry {
	union {
		ULONG64 all;
		struct {
			unsigned short offset_low;
			unsigned short selector;
			unsigned char ist_index : 3;  //!< [0:2]
			unsigned char reserved : 5;   //!< [3:7]
			unsigned char type : 5;       //!< [8:12]
			unsigned char dpl : 2;        //!< [13:14]
			unsigned char present : 1;    //!< [15]
			unsigned short offset_middle;
		} fields;
	}idtEntry;
	ULONG32 offset_high;
	ULONG32 reserved;
}KidtEntry;


typedef union _SegmentSelector {
	unsigned short all;
	struct {
		unsigned short rpl : 2;  //!< Requested Privilege Level
		unsigned short ti : 1;   //!< Table Indicator
		unsigned short index : 13;
	} fields;
}SegmentSelector;


#include <poppack.h>


typedef union _SegmentDescriptor {

	ULONG64 all;
	struct
	{
		ULONG64 limit_low : 16;
		ULONG64 base_low : 16;
		ULONG64 base_mid : 8;
		ULONG64 type : 4;
		ULONG64 system : 1;
		ULONG64 dpl : 2;
		ULONG64 present : 1;
		ULONG64 limit_high : 4;
		ULONG64 avl : 1;
		ULONG64 l : 1;  //!< 64-bit code segment (IA-32e mode only)
		ULONG64 db : 1;
		ULONG64 gran : 1;
		ULONG64 base_high : 8;
	} fields;


}SegmentDescriptor;

typedef struct _SegmentDesctiptorX64 {
	SegmentDescriptor descriptor;
	ULONG32 base_upper32;
	ULONG32 reserved;
}SegmentDesctiptorX64;

typedef union _VmxRegmentDescriptorAccessRight 
{
	unsigned int all;
	struct {
		unsigned type : 4;        //!< [0:3]
		unsigned system : 1;      //!< [4]
		unsigned dpl : 2;         //!< [5:6]
		unsigned present : 1;     //!< [7]
		unsigned reserved1 : 4;   //!< [8:11]
		unsigned avl : 1;         //!< [12]
		unsigned l : 1;           //!< [13] Reserved (except for CS) 64-bit mode
		unsigned db : 1;          //!< [14]
		unsigned gran : 1;        //!< [15]
		unsigned unusable : 1;    //!< [16] Segment unusable
		unsigned reserved2 : 15;  //!< [17:31]
	} fields;
}VmxRegmentDescriptorAccessRight;


/************************************************以下是寄存器相关定义************************************************/
typedef union _FlagRegister {
	ULONG_PTR all;
	struct {
		ULONG_PTR cf : 1;          //!< [0] Carry flag
		ULONG_PTR reserved1 : 1;   //!< [1] Always 1
		ULONG_PTR pf : 1;          //!< [2] Parity flag
		ULONG_PTR reserved2 : 1;   //!< [3] Always 0
		ULONG_PTR af : 1;          //!< [4] Borrow flag
		ULONG_PTR reserved3 : 1;   //!< [5] Always 0
		ULONG_PTR zf : 1;          //!< [6] Zero flag
		ULONG_PTR sf : 1;          //!< [7] Sign flag
		ULONG_PTR tf : 1;          //!< [8] Trap flag
		ULONG_PTR intf : 1;        //!< [9] Interrupt flag
		ULONG_PTR df : 1;          //!< [10] Direction flag
		ULONG_PTR of : 1;          //!< [11] Overflow flag
		ULONG_PTR iopl : 2;        //!< [12:13] I/O privilege level
		ULONG_PTR nt : 1;          //!< [14] Nested task flag
		ULONG_PTR reserved4 : 1;   //!< [15] Always 0
		ULONG_PTR rf : 1;          //!< [16] Resume flag
		ULONG_PTR vm : 1;          //!< [17] Virtual 8086 mode
		ULONG_PTR ac : 1;          //!< [18] Alignment check
		ULONG_PTR vif : 1;         //!< [19] Virtual interrupt flag
		ULONG_PTR vip : 1;         //!< [20] Virtual interrupt pending
		ULONG_PTR id : 1;          //!< [21] Identification flag
		ULONG_PTR reserved5 : 10;  //!< [22:31] Always 0
	} fields;
}FlagRegister;

typedef struct _GpRegistersX64 {
	ULONG_PTR r15;
	ULONG_PTR r14;
	ULONG_PTR r13;
	ULONG_PTR r12;
	ULONG_PTR r11;
	ULONG_PTR r10;
	ULONG_PTR r9;
	ULONG_PTR r8;
	ULONG_PTR di;
	ULONG_PTR si;
	ULONG_PTR bp;
	ULONG_PTR sp;
	ULONG_PTR bx;
	ULONG_PTR dx;
	ULONG_PTR cx;
	ULONG_PTR ax;
}GpRegisters;


typedef union _Cr0 {
	ULONG_PTR all;
	struct {
		unsigned pe : 1;          //!< [0] Protected Mode Enabled
		unsigned mp : 1;          //!< [1] Monitor Coprocessor FLAG
		unsigned em : 1;          //!< [2] Emulate FLAG
		unsigned ts : 1;          //!< [3] Task Switched FLAG
		unsigned et : 1;          //!< [4] Extension Type FLAG
		unsigned ne : 1;          //!< [5] Numeric Error
		unsigned reserved1 : 10;  //!< [6:15]
		unsigned wp : 1;          //!< [16] Write Protect
		unsigned reserved2 : 1;   //!< [17]
		unsigned am : 1;          //!< [18] Alignment Mask
		unsigned reserved3 : 10;  //!< [19:28]
		unsigned nw : 1;          //!< [29] Not Write-Through
		unsigned cd : 1;          //!< [30] Cache Disable
		unsigned pg : 1;          //!< [31] Paging Enabled
	} fields;
}Cr0;

/// See: CONTROL REGISTERS
typedef union _Cr4 {
	ULONG_PTR all;
	struct {
		unsigned vme : 1;         //!< [0] Virtual Mode Extensions
		unsigned pvi : 1;         //!< [1] Protected-Mode Virtual Interrupts
		unsigned tsd : 1;         //!< [2] Time Stamp Disable
		unsigned de : 1;          //!< [3] Debugging Extensions
		unsigned pse : 1;         //!< [4] Page Size Extensions
		unsigned pae : 1;         //!< [5] Physical Address Extension
		unsigned mce : 1;         //!< [6] Machine-Check Enable
		unsigned pge : 1;         //!< [7] Page Global Enable
		unsigned pce : 1;         //!< [8] Performance-Monitoring Counter Enable
		unsigned osfxsr : 1;      //!< [9] OS Support for FXSAVE/FXRSTOR
		unsigned osxmmexcpt : 1;  //!< [10] OS Support for Unmasked SIMD Exceptions
		unsigned reserved1 : 2;   //!< [11:12]
		unsigned vmxe : 1;        //!< [13] Virtual Machine Extensions Enabled
		unsigned smxe : 1;        //!< [14] SMX-Enable Bit
		unsigned reserved2 : 2;   //!< [15:16]
		unsigned pcide : 1;       //!< [17] PCID Enable
		unsigned osxsave : 1;  //!< [18] XSAVE and Processor Extended States-Enable
		unsigned reserved3 : 1;  //!< [19]
		unsigned smep : 1;  //!< [20] Supervisor Mode Execution Protection Enable
		unsigned smap : 1;  //!< [21] Supervisor Mode Access Protection Enable
	} fields;
}Cr4;

/// See: Debug Status Register (DR6)
typedef union _Dr6 {
	ULONG_PTR all;
	struct {
		unsigned b0 : 1;          //!< [0] Breakpoint Condition Detected 0
		unsigned b1 : 1;          //!< [1] Breakpoint Condition Detected 1
		unsigned b2 : 1;          //!< [2] Breakpoint Condition Detected 2
		unsigned b3 : 1;          //!< [3] Breakpoint Condition Detected 3
		unsigned reserved1 : 8;   //!< [4:11] Always 1
		unsigned reserved2 : 1;   //!< [12] Always 0
		unsigned bd : 1;          //!< [13] Debug Register Access Detected
		unsigned bs : 1;          //!< [14] Single Step
		unsigned bt : 1;          //!< [15] Task Switch
		unsigned rtm : 1;         //!< [16] Restricted Transactional Memory
		unsigned reserved3 : 15;  //!< [17:31] Always 1
	} fields;
}Dr6;

/// See: Debug Control Register (DR7)
typedef union _Dr7 {
	ULONG_PTR all;
	struct {
		unsigned l0 : 1;         //!< [0] Local Breakpoint Enable 0
		unsigned g0 : 1;         //!< [1] Global Breakpoint Enable 0
		unsigned l1 : 1;         //!< [2] Local Breakpoint Enable 1
		unsigned g1 : 1;         //!< [3] Global Breakpoint Enable 1
		unsigned l2 : 1;         //!< [4] Local Breakpoint Enable 2
		unsigned g2 : 1;         //!< [5] Global Breakpoint Enable 2
		unsigned l3 : 1;         //!< [6] Local Breakpoint Enable 3
		unsigned g3 : 1;         //!< [7] Global Breakpoint Enable 3
		unsigned le : 1;         //!< [8] Local Exact Breakpoint Enable
		unsigned ge : 1;         //!< [9] Global Exact Breakpoint Enable
		unsigned reserved1 : 1;  //!< [10] Always 1
		unsigned rtm : 1;        //!< [11] Restricted Transactional Memory
		unsigned reserved2 : 1;  //!< [12] Always 0
		unsigned gd : 1;         //!< [13] General Detect Enable
		unsigned reserved3 : 2;  //!< [14:15] Always 0
		unsigned rw0 : 2;        //!< [16:17] Read / Write 0
		unsigned len0 : 2;       //!< [18:19] Length 0
		unsigned rw1 : 2;        //!< [20:21] Read / Write 1
		unsigned len1 : 2;       //!< [22:23] Length 1
		unsigned rw2 : 2;        //!< [24:25] Read / Write 2
		unsigned len2 : 2;       //!< [26:27] Length 2
		unsigned rw3 : 2;        //!< [28:29] Read / Write 3
		unsigned len3 : 2;       //!< [30:31] Length 3
	} fields;
}Dr7;


/************************************************以下是mtrr相关定义************************************************/



/************************************************以下是vm 执行域相关定义************************************************/

typedef union _VmxProcessorBasedControls
{
	
	unsigned int all;
	struct {
		unsigned reserved1 : 2;                   //!< [0:1]
		unsigned interrupt_window_exiting : 1;    //!< [2]
		unsigned use_tsc_offseting : 1;           //!< [3]
		unsigned reserved2 : 3;                   //!< [4:6]
		unsigned hlt_exiting : 1;                 //!< [7]
		unsigned reserved3 : 1;                   //!< [8]
		unsigned invlpg_exiting : 1;              //!< [9]
		unsigned mwait_exiting : 1;               //!< [10]
		unsigned rdpmc_exiting : 1;               //!< [11]
		unsigned rdtsc_exiting : 1;               //!< [12]
		unsigned reserved4 : 2;                   //!< [13:14]
		unsigned cr3_load_exiting : 1;            //!< [15]
		unsigned cr3_store_exiting : 1;           //!< [16]
		unsigned reserved5 : 2;                   //!< [17:18]
		unsigned cr8_load_exiting : 1;            //!< [19]
		unsigned cr8_store_exiting : 1;           //!< [20]
		unsigned use_tpr_shadow : 1;              //!< [21]
		unsigned nmi_window_exiting : 1;          //!< [22]
		unsigned mov_dr_exiting : 1;              //!< [23]
		unsigned unconditional_io_exiting : 1;    //!< [24]
		unsigned use_io_bitmaps : 1;              //!< [25]
		unsigned reserved6 : 1;                   //!< [26]
		unsigned monitor_trap_flag : 1;           //!< [27]
		unsigned use_msr_bitmaps : 1;             //!< [28]
		unsigned monitor_exiting : 1;             //!< [29]
		unsigned pause_exiting : 1;               //!< [30]
		unsigned activate_secondary_control : 1;  //!< [31]
	} fields;
}VmxProcessorBasedControls;

typedef union _VmxSecondaryProcessorBasedControls 
{
	unsigned int all;
	struct {
		unsigned virtualize_apic_accesses : 1;            //!< [0]
		unsigned enable_ept : 1;                          //!< [1]
		unsigned descriptor_table_exiting : 1;            //!< [2]
		unsigned enable_rdtscp : 1;                       //!< [3]
		unsigned virtualize_x2apic_mode : 1;              //!< [4]
		unsigned enable_vpid : 1;                         //!< [5]
		unsigned wbinvd_exiting : 1;                      //!< [6]
		unsigned unrestricted_guest : 1;                  //!< [7]
		unsigned apic_register_virtualization : 1;        //!< [8]
		unsigned virtual_interrupt_delivery : 1;          //!< [9]
		unsigned pause_loop_exiting : 1;                  //!< [10]
		unsigned rdrand_exiting : 1;                      //!< [11]
		unsigned enable_invpcid : 1;                      //!< [12]
		unsigned enable_vm_functions : 1;                 //!< [13]
		unsigned vmcs_shadowing : 1;                      //!< [14]
		unsigned reserved1 : 1;                           //!< [15]
		unsigned rdseed_exiting : 1;                      //!< [16]
		unsigned reserved2 : 1;                           //!< [17]
		unsigned ept_violation_ve : 1;                    //!< [18]
		unsigned reserved3 : 1;                           //!< [19]
		unsigned enable_xsaves_xstors : 1;                //!< [20]
		unsigned reserved4 : 1;                           //!< [21]
		unsigned mode_based_execute_control_for_ept : 1;  //!< [22]
		unsigned reserved5 : 2;                           //!< [23:24]
		unsigned use_tsc_scaling : 1;                     //!< [25]
	} fields;
}VmxSecondaryProcessorBasedControls;

typedef union _VmxPinBasedControls 
{
	unsigned int all;
	struct {
		unsigned external_interrupt_exiting : 1;    //!< [0]
		unsigned reserved1 : 2;                     //!< [1:2]
		unsigned nmi_exiting : 1;                   //!< [3]
		unsigned reserved2 : 1;                     //!< [4]
		unsigned virtual_nmis : 1;                  //!< [5]
		unsigned activate_vmx_peemption_timer : 1;  //!< [6]
		unsigned process_posted_interrupts : 1;     //!< [7]
	} fields;
}VmxPinBasedControls;



/************************************************以下是vm entry控制域相关定义************************************************/



typedef union _VmxVmEntryControls 
{
	unsigned int all;
	struct {
		unsigned reserved1 : 2;                          //!< [0:1]
		unsigned load_debug_controls : 1;                //!< [2]
		unsigned reserved2 : 6;                          //!< [3:8]
		unsigned ia32e_mode_guest : 1;                   //!< [9]
		unsigned entry_to_smm : 1;                       //!< [10]
		unsigned deactivate_dual_monitor_treatment : 1;  //!< [11]
		unsigned reserved3 : 1;                          //!< [12]
		unsigned load_ia32_perf_global_ctrl : 1;         //!< [13]
		unsigned load_ia32_pat : 1;                      //!< [14]
		unsigned load_ia32_efer : 1;                     //!< [15]
		unsigned load_ia32_bndcfgs : 1;                  //!< [16]
		unsigned conceal_vmentries_from_intel_pt : 1;    //!< [17]
	} fields;
}VmxVmEntryControls;


enum InterruptionType 
{
	kExternalInterrupt = 0,
	kReserved = 1,  // Not used for VM-Exit
	kNonMaskableInterrupt = 2,
	kHardwareException = 3,			//包括#DF,TS,NP,SS,GP,PF,AC		
	kSoftwareInterrupt = 4,            // Not used for VM-Exit
	kPrivilegedSoftwareException = 5,  // Not used for VM-Exit
	kSoftwareException = 6,
	kOtherEvent = 7,  // Not used for VM-Exit
};

enum InterruptionVector 
{
	kDivideErrorException = 0,         //!< Error code: None
	kDebugException = 1,               //!< Error code: None
	kNmiInterrupt = 2,                 //!< Error code: N/A
	kBreakpointException = 3,          //!< Error code: None
	kOverflowException = 4,            //!< Error code: None
	kBoundRangeExceededException = 5,  //!< Error code: None
	kInvalidOpcodeException = 6,       //!< Error code: None
	kDeviceNotAvailableException = 7,  //!< Error code: None
	kDoubleFaultException = 8,         //!< Error code: Yes
	kCoprocessorSegmentOverrun = 9,    //!< Error code: None
	kInvalidTssException = 10,         //!< Error code: Yes
	kSegmentNotPresent = 11,           //!< Error code: Yes
	kStackFaultException = 12,         //!< Error code: Yes
	kGeneralProtectionException = 13,  //!< Error code: Yes
	kPageFaultException = 14,          //!< Error code: Yes
	kx87FpuFloatingPointError = 16,    //!< Error code: None
	kAlignmentCheckException = 17,     //!< Error code: Yes
	kMachineCheckException = 18,       //!< Error code: None
	kSimdFloatingPointException = 19,  //!< Error code: None
	kVirtualizationException = 20,     //!< Error code: None
};

typedef union _VmEntryInterruptionInformationField
{
	ULONG32 all;
	struct {
		ULONG32 vector : 8;              //!< [0:7]  InterruptionVector
		ULONG32 interruption_type : 3;   //!< [8:10] InterruptionType
		ULONG32 deliver_error_code : 1;  //!< [11]
		ULONG32 reserved : 19;           //!< [12:30]
		ULONG32 valid : 1;               //!< [31]
	} fields;
}VmEntryInterruptionInformationField;



/************************************************以下是vm exit控制域相关定义************************************************/


typedef union _VmxVmExitControls
{
	unsigned int all;
	struct {
		unsigned reserved1 : 2;                        //!< [0:1]
		unsigned save_debug_controls : 1;              //!< [2]
		unsigned reserved2 : 6;                        //!< [3:8]
		unsigned host_address_space_size : 1;          //!< [9]
		unsigned reserved3 : 2;                        //!< [10:11]
		unsigned load_ia32_perf_global_ctrl : 1;       //!< [12]
		unsigned reserved4 : 2;                        //!< [13:14]
		unsigned acknowledge_interrupt_on_exit : 1;    //!< [15]
		unsigned reserved5 : 2;                        //!< [16:17]
		unsigned save_ia32_pat : 1;                    //!< [18]
		unsigned load_ia32_pat : 1;                    //!< [19]
		unsigned save_ia32_efer : 1;                   //!< [20]
		unsigned load_ia32_efer : 1;                   //!< [21]
		unsigned save_vmx_preemption_timer_value : 1;  //!< [22]
		unsigned clear_ia32_bndcfgs : 1;               //!< [23]
		unsigned conceal_vmexits_from_intel_pt : 1;    //!< [24]
	} fields;
}VmxVmExitControls;

//余下几个都是count和msr的值相关
//..............

/************************************************以下是vm exit信息域相关定义************************************************/



//reason
enum VmxExitReason 
{
	//软件异常导致的,要求异常位图中设置;出现了不可屏蔽中断Nmi并且要求vm执行域的NmiExit置1
	ExitExceptionOrNmi = 0,
	//An external interrupt arrived and the “external-interrupt exiting” VM-execution control was 1.
	ExitExternalInterrupt = 1,
	//3重异常,对它的处理直接蓝屏;The logical processor encountered an exception while attempting to call the double-fault handler and that exception did not itself cause a VM exit due to the exception bitmap
	ExitTripleFault = 2,
	
	
	//这几个没有控制域来进行关闭,但很少发生
	//An INIT signal arrived
	ExitInit = 3,
	//A SIPI arrived while the logical processor was in the “wait-for-SIPI” state.
	ExitSipi = 4,
	//An SMI arrived immediately after retirement of an I/O instruction and caused an SMM VM exit
	ExitIoSmi = 5,
	//An SMI arrived and caused an SMM VM exit (see Section 34.15.2) but not immediately after retirement of an I/O instruction
	ExitOtherSmi = 6,
	
	
	//At the beginning of an instruction, RFLAGS.IF was 1; events were not blocked by STI or by MOV SS; and the “interrupt-window exiting” VM-execution control was 1.
	ExitPendingInterrupt = 7,
	//At the beginning of an instruction, there was no virtual-NMI blocking; events were not blocked by MOV SS; and the “NMI-window exiting” VM-execution control was 1.
	ExitNmiWindow = 8,
	
	//必须处理 由指令引发的无条件vmexit,也无法在控制域中关闭
	// Guest software attempted a task switch.
	ExitTaskSwitch = 9,
	ExitCpuid = 10,
	ExitGetSec = 11,

	//Guest software attempted to execute HLT and the “HLT exiting” VM-execution control was 1.
	ExitHlt = 12,


	//必须处理  Guest software attempted to execute INVD.无法在控制域中关闭
	ExitInvd = 13,

	//Guest software attempted to execute INVLPG and the “INVLPG exiting” VM-execution control was 1.
	ExitInvlpg = 14,
	//Guest software attempted to execute RDPMC and the “RDPMC exiting” VM-execution control was 1.
	ExitRdpmc = 15,
	//Guest software attempted to execute RDTSC and the “RDTSC exiting” VM-execution control was 1.
	ExitRdtsc = 16,


	//Guest software attempted to execute RSM in SMM.直接忽略
	ExitRsm = 17,
	
	//必须处理 
	ExitVmcall = 18,
	ExitVmclear = 19,
	ExitVmlaunch = 20,
	ExitVmptrld = 21,
	ExitVmptrst = 22,
	ExitVmread = 23,
	ExitVmresume = 24,
	ExitVmwrite = 25,
	ExitVmoff = 26,
	ExitVmon = 27,

	//Guest software attempted to access CR0, CR3, CR4, or CR8 using CLTS, LMSW, or MOV CR and the VM-execution control fields 
	//indicate that a VM exit should occur (see Section 25.1 for details). This basic exit reason is not used for trap-like VM exits 
	//following executions of the MOV to CR8 instruction when the “use TPR shadow” VM-execution control is 1.
	//Such VM exits instead use basic exit reason 43.
	ExitCrAccess = 28,
	//Guest software attempted a MOV to or from a debug register and the “MOV-DR exiting” VM-execution control was 1.
	ExitDrAccess = 29,

	//io指令和msr访问都可以进行禁用.这里需要将use I/O bitmaps域置0,并且unconditional I/O exiting置0
	//IN, INS/INSB/INSW/INSD, OUT, OUTS/OUTSB/OUTSW/OUTSD
	//Guest software attempted to execute an I/O instruction and either: 1: The “use I/O bitmaps” VM-execution control was 0 
	//and the “unconditional I/O exiting” VM-execution control was 1. 2: The “use I/O bitmaps” VM-execution control was 1 
	//and a bit in the I/O bitmap associated with one of the ports accessed by the I/O instruction was 1.
	ExitIoInstruction = 30,

	//同理,禁用方式如上
	//Guest software attempted to execute RDMSR and either: 1: The “use MSR bitmaps” VM-execution control was 0. 
	//2: The value of RCX is neither in the range 00000000H – 00001FFFH nor in the range C0000000H – C0001FFFH. 越界意味着#GP异常
	//3: The value of RCX was in the range 00000000H – 00001FFFH and the nth bit in read bitmap for low MSRs is 1, where n was the value of RCX.
	//4: The value of RCX is in the range C0000000H – C0001FFFH and the nth bit in read bitmap for high MSRs is 1, where n is the value of RCX & 00001FFFH.
	ExitMsrRead = 31,
	ExitMsrWrite = 32,

	//致命错误 A VM entry failed one of the checks identified in Section 26.3.1.
	ExitInvalidGuestState = 33,  // See: BASIC VM-ENTRY CHECKS
	//A VM entry failed in an attempt to load MSRs. 
	ExitMsrLoading = 34,
	ExitUndefined35 = 35,
	//Guest software attempted to execute MWAIT and the “MWAIT exiting” VM-execution control was 1.
	ExitMwaitInstruction = 36,
	//A VM entry occurred due to the 1-setting of the “monitor trap flag” VM-execution control and injection of an MTF VM exit as part of VM entry.
	ExitMonitorTrapFlag = 37,
	ExitUndefined38 = 38,
	//Guest software attempted to execute MONITOR and the “MONITOR exiting” VM-execution control was 1.
	ExitMonitorInstruction = 39,
	//Either guest software attempted to execute PAUSE and the “PAUSE exiting” VM-execution control was 1 or 
	//the “PAUSE-loop exiting” VM-execution control was 1 and guest software executed a PAUSE loop with execution time exceeding PLE_Window
	ExitPauseInstruction = 40,
	//致命错误A machine-check event occurred during VM entry
	ExitMachineCheck = 41,
	ExitUndefined42 = 42,
	//The logical processor determined that the value of bits 7:4 of the byte at offset 080H on the virtual-APIC page 
	//was below that of the TPR threshold VM-execution control field while the “use TPR shadow” VMexecution control was 1 either as part of TPR virtualization (Section 29.1.2) or VM entry 
	ExitTprBelowThreshold = 43,
	//Guest software attempted to access memory at a physical address on the APIC-access page 
    //and the “virtualize APIC accesses” VM-execution control was 1
	ExitApicAccess = 44,
	//EOI virtualization was performed for a virtual interrupt whose vector indexed a bit set in the EOIexit bitmap
	ExitVirtualizedEoi = 45,
	//Guest software attempted to execute LGDT, LIDT, SGDT, or SIDT and the “descriptor-table exiting” VM-execution control was 1.
	ExitGdtrOrIdtrAccess = 46,
	//Guest software attempted to execute LLDT, LTR, SLDT, or STR and the “descriptor-table exiting” VM-execution control was 1
	ExitLdtrOrTrAccess = 47,
	//An attempt to access memory with a guest-physical address was disallowed by the configuration of the EPT paging structures.
	ExitEptViolation = 48,
	//致命错误An attempt to access memory with a guest-physical address encountered a misconfigured EPT paging-structure entry.
	ExitEptMisconfig = 49,
	//必须处理 Guest software attempted to execute INVEPT.
	ExitInvept = 50,
	//Guest software attempted to execute RDTSCP and the “enable RDTSCP” and “RDTSC exiting” VM-execution controls were both 1.
	ExitRdtscp = 51,
	//The preemption timer counted down to zero.
	ExitVmxPreemptionTime = 52,
	//必须处理 Guest software attempted to execute INVVPID.
	ExitInvvpid = 53,
	//Guest software attempted to execute WBINVD and the “WBINVD exiting” VM-execution control was 1.
	ExitWbinvd = 54,
	//必须处理 Guest software attempted to execute XSETBV.
	ExitXsetbv = 55,
	//Guest software completed a write to the virtual-APIC page that must be virtualized by VMM software
	ExitApicWrite = 56,
	//Guest software attempted to execute RDRAND and the “RDRAND exiting” VM-execution control was 1.
	ExitRdrand = 57,
	//Guest software attempted to execute INVPCID and the “enable INVPCID” and “INVLPG exiting” VM-execution controls were both 1.
	ExitInvpcid = 58,
	//可以关闭 Guest software invoked a VM function with the VMFUNC instruction and the VM function 
	//either was not enabled or generated a function-specific condition causing a VM exit.
	ExitVmfunc = 59,
	//可以关闭 Guest software attempted to execute ENCLS and “enable ENCLS exiting” VM-execution control was 1 and either (1) EAX < 63 
	//and the corresponding bit in the ENCLS-exiting bitmap is 1; or (2) EAX ≥ 63 and bit 63 in the ENCLS-exiting bitmap is 1
	ExitUndefined60 = 60,
	//可以关闭 Guest software attempted to execute RDSEED and the “RDSEED exiting” VM-execution control was 1.
	ExitRdseed = 61,
	//The processor attempted to create a page-modification log entry and the value of the PML index was not in the range 0–511.
	ExitUndefined62 = 62,
	//可以关闭 Guest software attempted to execute XSAVES, the “enable XSAVES/XRSTORS” was 1, 
	//and a bit was set in the logical-AND of the following three values: EDX:EAX, the IA32_XSS MSR, and the XSS-exiting bitmap.
	ExitXsaves = 63,
	//可以关闭 Guest software attempted to execute XRSTORS, the “enable XSAVES/XRSTORS” was 1, 
	//and a bit was set in the logical-AND of the following three values: EDX:EAX, the IA32_XSS MSR, and the XSS-exiting bitmap.
	ExitXrstors = 64,
};


typedef union _VmExitInformation
{
	unsigned int all;
	struct
	{
		unsigned short reason;                     //!< [0:15] VmxExitReason
		unsigned short reserved1 : 12;             //!< [16:30]
		unsigned short pending_mtf_vm_exit : 1;    //!< [28]
		unsigned short vm_exit_from_vmx_root : 1;  //!< [29]
		unsigned short reserved2 : 1;              //!< [30]
		unsigned short vm_entry_failure : 1;       //!< [31]
	} fields;
}VmExitInformation;
//qualification
//Exit Qualification for Debug Exceptions

enum SourceTaskSwitch
{
	TsCall = 0,
	TsIret = 1,
	TsJmp = 2,
	TsTaskGate = 3

};
enum MovCrAccessType 
{
	AcMoveToCr = 0,
	AcMoveFromCr,
	AcClts,
	AcLmsw,
};

enum AcRegister
{
	AcRax=0,
	AcRcx,
	AcRdx, 
	AcRbx,
	AcRsp,
	AcRbp,
	AcRsi,
	AcRdi,
	AcR8,
	AcR9,
	AcR10,
	AcR11,
	AcR12,
	AcR13,
	AcR14,
	AcR15,

};


enum MovDrDirection 
{
	MoveToDr = 0,
	MoveFromDr,
};

enum IoInstSizeOfAccess
{
	AIo1Byte = 0,
	AIo2Byte = 1,
	AIo4Byte = 3,
};


enum IoInstDirection
{
	AIoOut = 0,
	AIoIn = 1,
};


typedef union _ExitQualification
{
	ULONG_PTR all;
	struct 
	{
		ULONG_PTR Bx : 4;//[3:0] 表示调试寄存器0123哪个被触发了
		ULONG_PTR Reserved1 : 9;//[12:4]
		ULONG_PTR BD : 1;//[13]
		ULONG_PTR BS : 1;//[14]
		ULONG_PTR Reserved2 : 49;//[63:15]

	}DebugExceptions;

	struct
	{
		ULONG_PTR Selector : 16;//[15:0]
		ULONG_PTR Reserved1 : 14;//[29:16]
		ULONG_PTR Source : 2;//[31:30] SourceTaskSwitch
		ULONG_PTR Reserved2 : 32;//[63:32]

	}TaskSwitch;

	struct 
	{
		ULONG_PTR control_register : 4;   //!< [0:3]
		ULONG_PTR access_type : 2;        //!< [4:5] MovCrAccessType
		ULONG_PTR lmsw_operand_type : 1;  //!< [6]
		ULONG_PTR reserved1 : 1;          //!< [7]
		ULONG_PTR gp_register : 4;        //!< [8:11] AcRegister
		ULONG_PTR reserved2 : 4;          //!< [12:15]
		ULONG_PTR lmsw_source_data : 16;  //!< [16:31]
		ULONG_PTR reserved3 : 32;         //!< [32:63]

	}ControlRegisterAccesses;

	struct
	{
		ULONG_PTR debugl_register : 3;  //!< [0:2]
		ULONG_PTR reserved1 : 1;        //!< [3]
		ULONG_PTR direction : 1;        //!< [4] //MovDrDirection
		ULONG_PTR reserved2 : 3;        //!< [5:7]
		ULONG_PTR gp_register : 4;      //!< [8:11] AcRegister
		ULONG_PTR reserved3 : 20;       //!<
		ULONG_PTR reserved4 : 32;       //!< [12:63]

	}DebugRegisterAccesses;

	struct {
		ULONG_PTR size_of_access : 3;      //!< [0:2] IoInstSizeOfAccess
		ULONG_PTR direction : 1;           //!< [3]
		ULONG_PTR string_instruction : 1;  //!< [4]
		ULONG_PTR rep_prefixed : 1;        //!< [5]
		ULONG_PTR operand_encoding : 1;    //!< [6]
		ULONG_PTR reserved1 : 9;           //!< [7:15]
		ULONG_PTR port_number : 16;        //!< [16:31]
	} IoInstQualification;

	struct 
	{
		ULONG_PTR unused;

	}APICAccess;

	struct
	{

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
		ULONG64 unuse : 51;
	}EPTViolations;
}ExitQualification;




//VmExitInterruptionInformationField


typedef union _VmExitInterruptionInformationField 
{
	ULONG32 all;
	struct 
	{
		ULONG32 vector : 8;             //!< [0:7]   InterruptionVector
		ULONG32 interruption_type : 3;  //!< [8:10]  InterruptionType
		ULONG32 error_code_valid : 1;   //!< [11]
		ULONG32 nmi_unblocking : 1;     //!< [12]
		ULONG32 reserved : 18;          //!< [13:30]
		ULONG32 valid : 1;              //!< [31]
	} fields;
}VmExitInterruptionInformationField;



//VmExitInterruptionInformation error code
//7大硬件异常


//VmExitIDTVectoringInformationField
typedef union _VmExitIDTVectoringInformationField
{
	ULONG32 all;
	struct 
	{
		ULONG32 vector : 8;             //!< [0:7]
		ULONG32 interruption_type : 3;  //!< [8:10]
		ULONG32 error_code_valid : 1;   //!< [11]
		ULONG32 Undefined : 1;          //!< [12]
		ULONG32 reserved : 18;          //!< [13:30]
		ULONG32 valid : 1;              //!< [31]
	} fields;
}VmExitIDTVectoringInformationField;


//VmExitIDTVectoringInformationField error code
//7大硬件异常


//VmExitinstructionInformationField
enum IOSAddressSize
{
	IOSbit16=0,
	IOSbit32,
	IOSbit64
};


enum IOSSegmentRegister
{
	IOSES=0,
	IOSCS,
	IOSSS,
	IOSDS,
	IOSFS,
	IOSGS
};

enum Scaling 
{
	kNoScaling = 0,
	kScaleBy2,
	kScaleBy4,
	kScaleBy8,
};
enum GdtrOrIdtrInstructionIdentity 
{
	kSgdt = 0,
	kSidt,
	kLgdt,
	kLidt,
};

enum  LdtrOrTrInstructionIdentity 
{
	kSldt = 0,
	kStr,
	kLldt,
	kLtr,
};


typedef union _VmExitinstructionInformationField
{
	//Ins/Outs串指令
	ULONG32 all;
	struct
	{
		ULONG32 Undefined1 : 7;             //!< [0:6]
		ULONG32 AddressSize : 3;  //!< [7:9] IOSAddressSize
		ULONG32 Undefined2 : 5;             //!< [10:14]
		ULONG32 SegmentRegister : 3;          //!< [17:15] IOSSegmentRegister
		ULONG32 Undefined3 : 14;          //!< [31:18]
	} InsOuts;

	//PcidOrVpid指令信息
	struct 
	{

		ULONG32 scalling : 2;                //!< [0:1] Scaling
		ULONG32 reserved1 : 5;               //!< [2:6]
		ULONG32 address_size : 3;            //!< [7:9] //IOSAddressSize
		ULONG32 reserved2 : 1;               //!< [10]
		ULONG32 reserved3 : 4;               //!< [11:14]
		ULONG32 segment_register : 3;        //!< [15:17]//IOSSegmentRegister
		ULONG32 index_register : 4;          //!< [18:21]//AcRegister
		ULONG32 index_register_invalid : 1;  //!< [22]
		ULONG32 base_register : 4;           //!< [23:26] //AcRegister
		ULONG32 base_register_invalid : 1;   //!< [27]
		ULONG32 index_register2 : 4;         //!< [28:31] //AcRegister
	}InvEptOrPcidOrVpidInstInformation;

	//gdtr,idtr指令
	struct  
	{

			ULONG32 scalling : 2;                //!< [0:1] Scaling
			ULONG32 reserved1 : 5;               //!< [2:6] 
			ULONG32 address_size : 3;            //!< [7:9]  IOSAddressSize
			ULONG32 reserved2 : 1;               //!< [10]
			ULONG32 operand_size : 1;            //!< [11]  IOSAddressSize
			ULONG32 reserved3 : 3;               //!< [12:14]
			ULONG32 segment_register : 3;        //!< [15:17] IOSSegmentRegister
			ULONG32 index_register : 4;          //!< [18:21] AcRegister
			ULONG32 index_register_invalid : 1;  //!< [22]
			ULONG32 base_register : 4;           //!< [23:26] AcRegister
			ULONG32 base_register_invalid : 1;   //!< [27]
			ULONG32 instruction_identity : 2;    //!< [28:29] GdtrOrIdtrInstructionIdentity
			ULONG32 reserved4 : 2;               //!< [30:31]
	}GdtrOrIdtrInstInformation;
	//ldtr, , tr指令
	struct  
	{

			ULONG32 scalling : 2;                //!< [0:1] Scaling
			ULONG32 reserved1 : 1;               //!< [2]
			ULONG32 register1 : 4;               //!< [3:6] AcRegister
			ULONG32 address_size : 3;            //!< [7:9] IOSAddressSize
			ULONG32 register_access : 1;         //!< [10]  1则访寄存器,0则访存
			ULONG32 reserved2 : 4;               //!< [11:14]
			ULONG32 segment_register : 3;        //!< [15:17] IOSSegmentRegister
			ULONG32 index_register : 4;          //!< [18:21] AcRegister
			ULONG32 index_register_invalid : 1;  //!< [22]
			ULONG32 base_register : 4;           //!< [23:26] AcRegister
			ULONG32 base_register_invalid : 1;   //!< [27]
			ULONG32 instruction_identity : 2;    //!< [28:29] LdtrOrTrInstructionIdentity
			ULONG32 reserved4 : 2;               //!< [30:31]
	}LdtrOrTrInstInformation;

	struct 
	{
		ULONG32 Undefined1 : 3;
		ULONG32 Register : 4;
		ULONG32 Undefined2 : 4;
		ULONG32 OperandSize : 2;
		ULONG32 Undefined3 : 19;


	}RDRANDOrRDSEEDInstInformation;

	//VMCLEAR, VMPTRLD, VMPTRST, VMXON, XRSTORS, and XSAVES
	struct
	{
		ULONG32 unuse;
	}VMXAndXInstInformation;

	//VMREAD and VMWRITE
	struct
	{
		ULONG32 unuse;
	}VMREADOrVMWRITE;
}VmExitinstructionInformationField;


//VmExitinstructionInformationField error code

enum VmxInstructionError 
{
	kVmcallInVmxRootOperation = 1,
	kVmclearInvalidAddress = 2,
	kVmclearVmxonPoiner = 3,
	kVmlaunchNonclearVmcs = 4,
	kVmresumeNonlaunchedVmcs = 5,
	kVmresumeAfterVmxoff = 6,
	kEntryInvalidControlField = 7,
	kEntryInvalidHostStateField = 8,
	kVmptrldInvalidAddress = 9,
	kVmptrldVmxonPointer = 10,
	kVmptrldIncorrectVmcsRevisionId = 11,
	kUnsupportedVmcsComponent = 12,
	kVmwriteReadOnlyVmcsComponent = 13,
	kVmxonInVmxRootOperation = 15,
	kEntryInvalidExecutiveVmcsPointer = 16,
	kEntryNonlaunchedExecutiveVmcs = 17,
	kEntryExecutiveVmcsPointerNonVmxonPointer = 18,
	kVmcallNonClearVmcs = 19,
	kVmcallInvalidVmExitControlFields = 20,
	kVmcallIncorrectMsegRevisionId = 22,
	kVmxoffUnderDualMonitorTreatmentOfSmisAndSmm = 23,
	kVmcallInvalidSmmMonitorFeatures = 24,
	kEntryInvalidVmExecutionControlFieldsInExecutiveVmcs = 25,
	kEntryEventsBlockedByMovSs = 26,
	kInvalidOperandToInveptInvvpid = 28,
};

#endif // !_IA32_H