PUBLIC AsmVmxLaunch
EXTERN VmexitHandler:PROC

;用于存储和恢复Guest环境
;相当于32位的pushed和poped
PUSHAQ MACRO
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    -1      ; 相当于push rsp
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
ENDM

POPAQ MACRO
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    add     rsp, 8    ; 相当于 pop rsp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
ENDM

.CONST 
VMX_OK                      EQU     0
VMX_ERROR_WITH_STATUS       EQU     1
VMX_ERROR_WITHOUT_STATUS    EQU     2

.CODE
;这个函数用于保存Guest环境后执行vmlaunch，再恢复Guest环境
;BOOLEAN AsmVmxLaunch(PVOID callBack,PVOID thisPoint);
AsmVmxLaunch PROC
	pushfq
	PUSHAQ
	
    mov rax,rcx;把InitVMCS函数指针放在rax
    mov rcx,rdx;在C++中调用成员函数要传入对象this指针,参数个数确定的时候，用rcx来传递,否则作为最后一个传
	mov rdx,rsp;传入InitVMCS的参数1 guestStack
	mov r8,VmLaunchToGuest;传入InitVMCS的参数2 guestResumeRip
	sub rsp,100h;提升栈顶，给一些局部变量分配足够的栈空间
	call rax;调用InitVMCS
	add rsp,100h
	
    ;若成功，不会执行到这里
	POPAQ
	popfq
	xor rax,rax
	ret

VmLaunchToGuest:

	POPAQ
	popfq
	xor rax,rax
	inc rax
	ret

AsmVmxLaunch ENDP

;拦截的VmExit事件触发的时候，从这里开始进入我们的处理函数VmexitHandler
AsmVmmEntryPoint PROC
	PUSHAQ			;当guest转入vmm时,通用寄存器并不会改变.而其它寄存器存放在vmcs guest域中,包括rflags

	mov rcx,rsp
	sub rsp,50h
	call VmexitHandler;该函数执行有三种结果,一种是遇到非预期的vmexit直接断点.返回0继续运行,需要vmresume. 返回1退出vmx,回到guest
	add rsp,50h
	test al,al
	jz ExitVmx		;返回0则退出vmx

	POPAQ
	vmresume		;会根据vmcs的guest域进行恢复guest状态,只是通用寄存器需要手动恢复
	jmp ErrorHandler	;如果回Guest失败才会执行这里
ExitVmx:
	POPAQ
	vmxoff			;执行完后rax=rflags,rdx=原来的栈,rcx=导致vmexit的下一条指令地址
	jz ErrorHandler             ; if (ZF) jmp
    jc ErrorHandler             ; if (CF) jmp
    push rax
    popfq                  ; rflags <= GuestFlags
    mov rsp, rdx            ; rsp <= GuestRsp
    push rcx
    ret                     ; jmp AddressToReturn
ErrorHandler:
    int 3
AsmVmmEntryPoint ENDP



AsmVmxCall PROC
    vmcall                  ; vmcall(hypercall_number, context)
    ret
AsmVmxCall ENDP


AsmInvd PROC
    invd
    ret
AsmInvd ENDP

AsmInvvpid PROC
    invvpid rcx, oword ptr [rdx]
    jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    xor rax, rax            ; return VMX_OK
    ret

errorWithoutCode:
    mov rax, VMX_ERROR_WITHOUT_STATUS
    ret

errorWithCode:
    mov rax, VMX_ERROR_WITH_STATUS
    ret
AsmInvvpid ENDP


; void AsmWriteGDT(_In_ const GDTR *gdtr);
AsmWriteGDT PROC
    lgdt fword ptr [rcx]
    ret
AsmWriteGDT ENDP

; void AsmWriteLDTR(_In_ USHORT local_segmeng_selector);
AsmWriteLDTR PROC
    lldt cx
    ret
AsmWriteLDTR ENDP

; USHORT AsmReadLDTR();
AsmReadLDTR PROC
    sldt ax
    ret
AsmReadLDTR ENDP

; void AsmWriteTR(_In_ USHORT task_register);
AsmWriteTR PROC
    ltr cx
    ret
AsmWriteTR ENDP

; USHORT AsmReadTR();
AsmReadTR PROC
    str ax
    ret
AsmReadTR ENDP

; void AsmWriteES(_In_ USHORT segment_selector);
AsmWriteES PROC
    mov es, cx
    ret
AsmWriteES ENDP

; USHORT AsmReadES();
AsmReadES PROC
    mov ax, es
    ret
AsmReadES ENDP

; void AsmWriteCS(_In_ USHORT segment_selector);
AsmWriteCS PROC
    mov cs, cx
    ret
AsmWriteCS ENDP

; USHORT AsmReadCS();
AsmReadCS PROC
    mov ax, cs
    ret
AsmReadCS ENDP

; void AsmWriteSS(_In_ USHORT segment_selector);
AsmWriteSS PROC
    mov ss, cx
    ret
AsmWriteSS ENDP

; USHORT AsmReadSS();
AsmReadSS PROC
    mov ax, ss
    ret
AsmReadSS ENDP

; void AsmWriteDS(_In_ USHORT segment_selector);
AsmWriteDS PROC
    mov ds, cx
    ret
AsmWriteDS ENDP

; USHORT AsmReadDS();
AsmReadDS PROC
    mov ax, ds
    ret
AsmReadDS ENDP

; void AsmWriteFS(_In_ USHORT segment_selector);
AsmWriteFS PROC
    mov fs, cx
    ret
AsmWriteFS ENDP

; USHORT AsmReadFS();
AsmReadFS PROC
    mov ax, fs
    ret
AsmReadFS ENDP

; void AsmWriteGS(_In_ USHORT segment_selector);
AsmWriteGS PROC
    mov gs, cx
    ret
AsmWriteGS ENDP

; USHORT AsmReadGS();
AsmReadGS PROC
    mov ax, gs
    ret
AsmReadGS ENDP

; ULONG_PTR AsmLoadAccessRightsByte(_In_ ULONG_PTR segment_selector);
AsmLoadAccessRightsByte PROC
    lar rax, rcx
    ret
AsmLoadAccessRightsByte ENDP

END