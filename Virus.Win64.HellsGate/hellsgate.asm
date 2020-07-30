; @file     main.c
; @author   Paul Laîné (@am0nsec) & smelly__vx (@RtlMateusz) 
; @version  1.0
; @brief    Dynamically extracting and invoking syscalls from in-memory modules.
; @details
; @link     https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf
;
; @copyright This project has been released under the GNU Public License v3 license.

.data
	wSystemCall DWORD 000h

.code 
	HellsGate PROC
		mov wSystemCall, 000h
		mov wSystemCall, ecx
		ret
	HellsGate ENDP

	HellDescent PROC
		mov r10, rcx
		mov eax, wSystemCall

		syscall
		ret
	HellDescent ENDP
end
