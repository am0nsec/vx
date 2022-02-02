
#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <locale.h>
#include <immintrin.h>

VOID RandomEngineKeyGen (
    _Inout_ __m128* Key
);

VOID Encoder(
	_In_    DWORD   dwNumberOfLoops,
	_Inout_ __m128* PointerToData,
	_In_    __m128* PointerToKey
);

VOID Decoder(
	_In_    DWORD   dwNumberOfLoops,
	_Inout_ __m128* PointerToData,
	_In_    __m128* PointerToControl
);

/**
 * @brief Print out the data in a C format
 * @param lpBuffer Pointer to the buffer
 * @param dwBufferSize Size of the buffer
*/
VOID __inline PrintData(
    _In_ CONST CHAR*  Prefix,
	_In_ CONST LPVOID lpBuffer,
	_In_ CONST DWORD  dwBufferSize
) {
    if (Prefix != NULL)
        printf("%s", Prefix);

	for (DWORD cx = 0x00; cx < dwBufferSize; cx++)
		printf("\\x%02x", ((UCHAR*)lpBuffer)[cx]);
	printf("\n\n");
}

// Arbitrary payload used as an example 
uint8_t g_Payload[] = 
"\x49\x20\x61\x6d\x20\x76\x65\x72\x79\x20\x74\x61\x6b\x65\x6e\x20"
"\x77\x69\x74\x68\x20\x74\x68\x65\x20\x67\x61\x6d\x65\x20\x5b\x2e"
"\x2e\x2e\x5d\x20\x62\x75\x74\x20\x49\x20\x61\x6d\x20\x6e\x6f\x74"
"\x20\x69\x6e\x20\x61\x20\x70\x6f\x73\x69\x74\x69\x6f\x6e\x20\x74"
"\x6f\x20\x73\x61\x63\x72\x69\x66\x69\x63\x65\x20\x74\x68\x65\x20"
"\x6e\x65\x63\x65\x73\x73\x61\x72\x79\x20\x69\x6e\x20\x74\x68\x65"
"\x20\x68\x6f\x70\x65\x20\x6f\x66\x20\x61\x63\x71\x75\x69\x72\x69"
"\x6e\x67\x20\x74\x68\x65\x20\x73\x75\x70\x65\x72\x66\x6c\x75\x6f"
"\x75\x73\x2e\x20\x2d\x2d\x20\x48\x65\x72\x6d\x61\x6e\x6e\x20\x00";

DWORD main() {

    // 1.Generate a random 128-bit key
    __m128 EncodingKey= { 0x00 };
    RandomEngineKeyGen(&EncodingKey);
    PrintData("[*] Encoding key:\n", &EncodingKey, sizeof(__m128));

    // 2. Get aligned size
   	DWORD dwAlignedSize = 0x00 + sizeof(g_Payload);
    while(dwAlignedSize % 0x10)
        dwAlignedSize++;
    printf("[*] Size after padding: %xh bytes\n", dwAlignedSize);

    // 3. Allocate memory and copy data
    __m128* lpAlignedData = calloc(0x01, dwAlignedSize);
    if (lpAlignedData == NULL)
		return EXIT_FAILURE;
    memcpy_s(lpAlignedData, dwAlignedSize, g_Payload, sizeof(g_Payload));

    // 4. Get control block for decoder
    __m128 ControlBlock = *lpAlignedData;
    PrintData("[*] Control block:\n", &ControlBlock, sizeof(__m128));
    printf("[*] Payload before decoding:\n%s\n\n", (CHAR*)lpAlignedData);

    // 5. Encode the data with the encoder
    Encoder((dwAlignedSize / 0x10), lpAlignedData, &EncodingKey);
    PrintData("[*] Data after encoding:\n", lpAlignedData, dwAlignedSize);

    // 6. Decode the payload with the brute-force decoder
    Decoder((dwAlignedSize / 0x10), lpAlignedData, &ControlBlock);
    printf("[*] Data after decoding:\n%s\n\n", (CHAR*)lpAlignedData);

    // x. Cleanup and exit
    return EXIT_SUCCESS;
}