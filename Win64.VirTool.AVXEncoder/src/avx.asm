bits 64
default rel

global RandomEngineKeyGen
global Encoder
global Decoder

%define xmmword oword

section .text

; Generate a 128-bits random value using CPU on-chip entropy 
RandomEngineKeyGen:
    push rcx           ; Save pointer to key
    mov edx, 0x10      ; Move number of bytes for the loop

    rdrand eax         ; Generand random number 
_loop_write:
    mov byte [rcx], al ; Move byte to __m128 structure
    inc rcx            ; Increment
    dec edx            ; Decrement
    jnz _loop_write    ; Loop for each bytes

    pop rcx            ; Restore pointer to key
    ret


; XOR encode a blob of data
Encoder:
    push rdx                         ; Save pointer to data

    vmovdqu xmm1, xmmword [r8]       ; Load the key
_encoder_loop:
    vxorpd xmm0, xmm1, xmmword [rdx] ; XOR encode 128-bit block
    vmovdqu xmmword [rdx], xmm0      ; Move encoded data

    add rdx, 0x10                    ; Move pointer
    loop _encoder_loop               ; Loop for each blocks

    pop rdx                          ; Restore pointer to data
    ret


; XOR decode a blob of data. Key is brute forced
Decoder:
    ; xmm0 The decoded data
    ; xmm1 The brute-forced key
    ; xmm2 The control-block
    ; xmm3 The packed-bytes set to 1
    push rdx                         ; Save pointer to data

    vpcmpeqw xmm3, xmm3, xmm3        ; Set all packed bytes to 1
    vmovdqu  xmm2, xmmword [r8]      ; Load the control block
    vxorpd   xmm1, xmm1, xmm1        ; Zero-out the XOR key
_brute_force_key:
    vpsubb xmm1, xmm1, xmm3          ; Substract 1 to all packed bytes
    
    vxorpd xmm0, xmm1, xmmword [rdx] ; XOR decode 128-bit block
    vcmppd xmm0, xmm0, xmm2, 0h      ; Compare the decoded data and the control block 

    vpextrb eax, xmm0, 0h            ; Extract the lowest byte from xmm0
    inc al                           ; al will be -1 if vcmppd failed so inc will lead for FALSE, otherwise TRUE
    jne _brute_force_key             ; Loop until found

_decode_loop:
    vxorpd xmm0, xmm1, xmmword [rdx] ; XOR encode 128-bit block
    vmovdqu xmmword [rdx], xmm0      ; Move encoded data

    add rdx, 0x10                    ; Move pointer
    loop _encoder_loop               ; Loop for each blocks

    pop rdx                          ; Restore pointer to data
    ret