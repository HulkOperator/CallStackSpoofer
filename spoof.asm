.code

STACK_INFO STRUCT
	pRtlUserThreadStart_RetAddr		DQ 1
	dwRtlUserThreadStart_Size		DQ 1

	pBaseThreadInitThunk_RedAddr	DQ 1
	dwBaseThreadInitThunk_Size		DQ 1

	pGadgetAddr						DQ 1
	dwGadget_Size					DQ 1

	pTargetFunction					DQ 1
	pRbx							DQ 1
	dwNumberOfArgs					DQ 1
	pArgs							DQ 1
STACK_INFO ENDS


Spoof PROC
	
	pop r15														; Top of the stack will have return address of the Function which has called this Spoof Function
																; When this Spoof function completes execution, we can use this value to resume the normal execution flow

	mov r13, rcx												; r13 now point to STACK_INFO struct

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;			Creating Synthetic Frames
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	push 0														; This will terminate the Stack Unwinding

	; Creating The First Thread Initialising Frame

	mov r10, [r13].STACK_INFO.dwRtlUserThreadStart_Size			; Size of RtlUserThreadStart
	sub rsp, r10
	mov r10, [r13].STACK_INFO.pRtlUserThreadStart_RetAddr
	push r10													; Pusing the Return Address to RtlUserThreadStart

	; Creating The Second Thread Initialising Frame

	mov r10, [r13].STACK_INFO.dwBaseThreadInitThunk_Size		; Size of BaseThreadInitThunk
	sub rsp, r10
	mov r10, [r13].STACK_INFO.pBaseThreadInitThunk_RedAddr
	push r10													; Pusing the Return Address to BaseThreadInitThunk

	; Creating the Gadget's Frame

	mov r10, [r13].STACK_INFO.dwGadget_Size						; Size of Gadget's Frame
	sub rsp, r10
	mov r10, [r13].STACK_INFO.pGadgetAddr	
	push r10													; Pushing the Return Address to Gadget's Address


	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;			Configuring Arguments
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	; Configuring first 4 arguments in the registers

	lea r10, [r13].STACK_INFO.pArgs
	mov rcx, [r10]
	mov rdx, [r10 + 8]
	mov r8, [r10 + 16]
	mov r9, [r10 + 24]

	mov rbp,  [r13].STACK_INFO.dwNumberOfArgs
	sub rbp, 4

	; Looping to Configure Additional Arguments on the Stack
loop_start:
	cmp rbp, 0
	jle setup_rbx
	mov r11, [r10 + rbp*8]
	mov [rsp + 40 + rbp*8], r11
	dec rbp
	jmp loop_start

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;			Setting Up RBX
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	; Configure the Pointer to "restore" in rbx

setup_rbx:
	mov r10, restore
	mov [r13].STACK_INFO.pRbx, r10
	lea rbx, [r13].STACK_INFO.pRbx
	
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;			Executing the Target WinAPI
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	; JMP to the Target Function

	mov r10, [r13].STACK_INFO.pTargetFunction
	jmp r10


	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;			Restoring the Stack
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	; Restoring the Stack to Original State (Before Spoof Function was called)

restore:
	add rsp, 24													; Reversing the effect of Pushing 3 return addresses

	mov r10, [r13].STACK_INFO.dwRtlUserThreadStart_Size
	add rsp, r10

	mov r10, [r13].STACK_INFO.dwBaseThreadInitThunk_Size
	add rsp, r10

	mov r10, [r13].STACK_INFO.dwGadget_Size
	add rsp, r10

	jmp r15

Spoof ENDP
end