; @file        SILVERHAND.ASM
; @date        24-02-2021
; @author      Paul L. (@am0nsec)
; @version     1.0
; @brief       AES-128 and AES-256 CBC Encryption and Decryption using AES-NI instruciton set.
; @details	
; @link        https://github.com/am0nsec/vx
; @copyright   This project has been released under the GNU Public License v3 license.

_TEXT SEGMENT

SiStartBlock PROC
SiStartBlock ENDP

;--------------------------------------------------------------------------------------------------
; Check whether the Intel/AMD CPU supports AES-NI instruction set.
;--------------------------------------------------------------------------------------------------
SiIsAESNIEnabled PROC
	xor ecx, ecx
	mov eax, 1
	cpuid

	and ecx, 2000000h
	cmp ecx, 2000000h
	jne error

success:
	mov eax, 1
	ret

error:
	xor eax, eax
	ret
SiIsAESNIEnabled ENDP

;--------------------------------------------------------------------------------------------------
; Generate random 128 or 256-bits of data.
; RCX - Pointer to a 128 or 256-bits memory location.
; RDX - Whether 256-bits of random data or 128-bits of random data
;--------------------------------------------------------------------------------------------------
SiGenerateRandom PROC
	push rcx
	mov rax, rcx

	; Check if 128 or 256 bits have to be generated.
	cmp dl, 01h
	je _256_bits
_128_bits:
	mov ecx, 02h
	jmp rdrand_loop
_256_bits:
	mov ecx, 04h

	; Generate random data
rdrand_loop:
	rdrand rbx
	mov qword ptr [rax], rbx
	add rax, 08h
	loop rdrand_loop

	pop rcx
	ret
SiGenerateRandom ENDP

;--------------------------------------------------------------------------------------------------
; Initialise key scheduler for encryption in AES-128.
; RCX - Pointer to the encryption key scheduler.
; RDX - Pointer to the 128-bits key.
;--------------------------------------------------------------------------------------------------
Si128KeyExpansion PROC
	mov rbx, rcx
	movdqu xmm0, xmmword ptr [rdx]

	; First round
	movdqu xmmword ptr [rbx], xmm0
	add rbx, 10h

	; Remaining rounds
	mov ecx, 0Ah
keys_loop:
	 aeskeygenassist xmm1, xmm0, 8h
	 pshufd xmm1, xmm1, 00ffh
	 vpslldq xmm2, xmm0, 04h
	 pxor xmm0, xmm2
	 vpslldq xmm2, xmm0, 04h
	 pxor xmm0, xmm2
	 vpslldq xmm2, xmm0, 04h
	 pxor xmm0, xmm2
	 pxor xmm0, xmm1
	 movdqu xmmword ptr [rbx], xmm0

	; Next element
	add rbx, 10h
	loop keys_loop

	ret
Si128KeyExpansion ENDP

;--------------------------------------------------------------------------------------------------
; Initialise key scheduler for encryption in AES-256.
; RCX - Pointer to the encryption key scheduler.
; RDX - Pointer to the 256-bits key.
;--------------------------------------------------------------------------------------------------
Si256KeyExpansion PROC
	mov rax, rcx

	movdqu xmm1, xmmword ptr [rdx]
	movdqa xmmword ptr [rax], xmm1

	movdqu xmm3, xmmword ptr [rdx + 10h]
	movdqa xmmword ptr [rax + 10h], xmm3

	; Loop through each iteration 
	mov ecx, 0Dh
	xor rbx, rbx
aeskeygenassist_loop:
	cmp bl, 00h
	je aes_assite_1

aes_assite_1:
	aeskeygenassist xmm2, xmm3, 40h
	pshufd xmm2, xmm2, 0ffh
	movdqa xmm4, xmm1
	pslldq xmm4, 04h
	pxor xmm1, xmm4
	pslldq xmm4, 04h
	pxor xmm1, xmm4
	pslldq xmm4, 04h
	pxor xmm1, xmm4
	pxor xmm1, xmm2
	movdqa xmmword ptr [rax], xmm1
	inc ebx
	jmp next_round

aes_assist_2:
	aeskeygenassist xmm2, xmm1, 00h
	pshufd xmm2, xmm2, 0aah
	movdqa xmm4, xmm3
	pslldq xmm4, 04h
	pxor xmm3, xmm4
	pslldq xmm4, 04h
	pxor xmm3, xmm4
	pslldq xmm4, 04h
	pxor xmm3, xmm4
	pxor xmm3, xmm2
	movdqa xmmword ptr [rax], xmm3
	dec ebx

	; Next index in the key scheduler table
next_round:
	add rax, 10h
	loop aeskeygenassist_loop
	ret
Si256KeyExpansion ENDP

;--------------------------------------------------------------------------------------------------
; Initialise key scheduler for decryption in AES-128.
; RCX - Pointer to the decryption key scheduler.
; RDX - Pointer to the encryption key scheduler.
;--------------------------------------------------------------------------------------------------
Si128InverseCipher PROC
	push rcx
	push rdx
	movdqu xmm0, xmmword ptr [rcx]
	movdqu xmm1, xmmword ptr [rdx]
	movdqu xmmword ptr [rcx], xmm1
	add rcx, 10h
	add rdx, 10h
	
	mov ebx, 09h
aesimc_loop:
	aesimc xmm1, xmmword ptr [rdx]
	movdqu xmmword ptr [rcx], xmm1

	add rcx, 10h
	add rdx, 10h
	dec ebx
	jnz aesimc_loop

	movdqu xmm1, xmmword ptr [rdx]
	movdqu xmmword ptr [rcx], xmm1
	
	pop rdx
	pop rcx
	ret
Si128InverseCipher ENDP

;--------------------------------------------------------------------------------------------------
; Initialise key scheduler for decryption in AES-256.
; RCX - Pointer to the decryption key scheduler.
; RDX - Pointer to the encryption key scheduler.
;--------------------------------------------------------------------------------------------------
Si256InverseCipher PROC
	push rcx
	push rdx
	push rax
	mov rax, rcx
	movdqu xmm1, xmmword ptr [rdx] 
	movdqu xmmword ptr [rax], xmm1
	add rax, 10h
	add rdx, 10h

	mov ecx, 0Dh
aesimc_loop:
	aesimc xmm1, xmmword ptr [rdx]
	movdqu xmmword ptr [rax], xmm1
	add rax, 10h
	add rdx, 10h
	loop aesimc_loop

	movdqu xmm1, xmmword ptr [rdx]
	movdqu xmmword ptr [rax], xmm1
	
	pop rax
	pop rdx
	pop rcx
	ret
Si256InverseCipher ENDP

;--------------------------------------------------------------------------------------------------
; Decrypt block of data in AES-256 or AES-128 mode.
; RCX - Pointer to a block of data to encrypt.
; RDX - Pointer to the previously encrypted block or IV
; R8  - Pointer to the key scheduler
; R9  - Whether this is AES-128 or AES-256.
;--------------------------------------------------------------------------------------------------
SiEncryptBlock PROC
	push r8
	mov rax, rcx

	; Copy block to XMM0 and XOR with previous block
	movdqu xmm0, xmmword ptr [rax]
	pxor xmm0, xmmword ptr [rdx]

	; Check whether this is AES-256 or AES-128
	cmp r9b, 1
	je aes_256_mode
aes_128_mode:
	mov ecx, 09h
	jmp first_round
aes_256_mode:
	mov ecx, 0Dh

	; First round will be a withening round
first_round:
	pxor xmm0, xmmword ptr [r8]
	add r8, 10h

	; Loop for the remaining rounds
aesenc_loop:
	aesenc xmm0, xmmword ptr [r8]
	add r8, 10h
	loop aesenc_loop

	; Last round
	aesenclast xmm0, xmmword ptr [r8]

	; Return the value
	movdqu xmmword ptr [rax], xmm0
	pop r8
	ret
SiEncryptBlock ENDP

;--------------------------------------------------------------------------------------------------
; Decrypt block of data in AES-256 or AES-128 mode.
; RCX - Pointer to a block of data to encrypt.
; RDX - Pointer to the previously encrypted block or IV
; R8  - Pointer to the key scheduler
; R9  - Whether this is AES-128 or AES-256.
;--------------------------------------------------------------------------------------------------
SiDecryptBlock PROC
	push r8
	mov rax, rcx

	; Copy block to decrypt XMM0
	movdqu xmm0, xmmword ptr [rax]

	; Check whether this is AES-256 or AES-128
	cmp r9b, 1
	je aes_256_mode
aes_128_mode:
	add r8, 0A0h
	mov ecx, 09h
	jmp first_round
aes_256_mode:
	add r8, 0E0h
	mov ecx, 0Dh

	; First round will be a withening round
first_round:
	pxor xmm0, xmmword ptr [r8]
	sub r8, 10h

	; Loop for the remaining rounds
aesdec_loop:
	aesdec xmm0, xmmword ptr [r8]
	sub r8, 10h
	loop aesdec_loop

	; Last round and XOR with previous block
	aesdeclast xmm0, xmmword ptr [r8]
	pxor xmm0, xmmword ptr [rdx]

	; Return value
	pop r8
	movdqu xmmword ptr [rax], xmm0
	ret
SiDecryptBlock ENDP

SiEndBlock PROC
SiEndBlock ENDP

; End of file.
_TEXT ENDS
END