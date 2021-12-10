#include <Windows.h>
#include <emmintrin.h>
#include <stdio.h>

extern void SiStartBlock();
extern void SiIsAESNIEnabled();
extern void SiGenerateRandom();
extern void Si128KeyExpansion();
extern void Si256KeyExpansion();
extern void Si128InverseCipher();
extern void Si256InverseCipher();
extern void SiEncryptBlock();
extern void SiDecryptBlock();
extern void SiEndBlock();

int main() {
	LPBYTE ip = &SiStartBlock;

	// Get list of rva
	printf("// SiIsAESNIEnabled   0x%08llx\n", (LPBYTE)&SiIsAESNIEnabled - ip);
	printf("// SiGenerateRandom   0x%08llx\n", (LPBYTE)&SiGenerateRandom - ip);
	printf("// Si128KeyExpansion  0x%08llx\n", (LPBYTE)&Si128KeyExpansion - ip);
	printf("// Si256KeyExpansion  0x%08llx\n", (LPBYTE)&Si256KeyExpansion - ip);
	printf("// Si128InverseCipher 0x%08llx\n", (LPBYTE)&Si128InverseCipher - ip);
	printf("// Si256InverseCipher 0x%08llx\n", (LPBYTE)&Si256InverseCipher - ip);
	printf("// SiEncryptBlock     0x%08llx\n", (LPBYTE)&SiEncryptBlock - ip);
	printf("// SiDecryptBlock     0x%08llx\n", (LPBYTE)&SiDecryptBlock - ip);
	printf("\n\n\n");

	DWORD cx = 0x00;
	printf("byte[] asm = new byte[] {");
	do {
		printf("0x%02x, ", (unsigned char)*ip);
		cx++;
	} while (ip++ != SiEndBlock);

	printf("};\n\nint NumberOfBytes = 0x%llx;", cx);
	return 0x00;
}

