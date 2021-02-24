/**
* @file        main.c
* @date        24-02-2021
* @author      Paul L. (@am0nsec)
* @version     1.0
* @brief       AES-128 and AES-256 CBC Encryption and Decryption using AES-NI instruciton set.
* @details	
* @link        https://github.com/am0nsec/vx
* @copyright   This project has been released under the GNU Public License v3 license.
*/
#include <Windows.h>   // Windows API
#include <stdio.h>     // Standard Input/Output library
#include <immintrin.h> // SSE2 intrinsics 

#include "silverhand.h"

/**
 * @brief Encrypt string with AES-128 CBC algorithm.
 * @param ppPlaintext Pointer to the plaintext to encrypt.
 * @param pdwPlaintextSize Pointer to the size of the plaintext to encrypt.
 * @param KeyScheduler Pointer to the key scheduler
 * @param pIv Pointer to the IV.
 * @param ppCipher Pointer to the cipher.
 * @param pdwCipherSize Pointer to the size of the cipher.
 * @return Whether the string has been encrypted.
*/
_Success_(return == S_OK) _Must_inspect_impl_
HRESULT Si128EncryptString(
	_In_    PVOID*   ppPlaintext,
	_In_    PDWORD   pdwPlaintextSize,
	_In_    __m128i* KeyScheduler,
	_In_    __m128i* pIv,
	_Inout_ PVOID*   ppCipher,
	_Out_   PDWORD   pdwCipherSize
) {
	if (ppPlaintext == NULL || pdwPlaintextSize == NULL || pdwCipherSize == NULL)
		return E_INVALIDARG;

	// Get the total size for blocks
	while (*pdwPlaintextSize % 0x10 != 0x00)
		(*pdwPlaintextSize)++;
	*pdwCipherSize = *pdwPlaintextSize;

	// Allocate memory for the copy of the cipher 
	HANDLE hProcessHandle = GetProcessHeap();
	if (ppCipher == NULL)
		return E_FAIL;
	*ppCipher = HeapAlloc(hProcessHandle, HEAP_ZERO_MEMORY, *pdwPlaintextSize);

	// Allocate memory for a the padded plaintext
	PVOID pPlaintextCopy = HeapAlloc(hProcessHandle, HEAP_ZERO_MEMORY, *pdwPlaintextSize);
	if (pPlaintextCopy == NULL) {
		HeapFree(hProcessHandle, 0x00, *ppCipher);
		return E_FAIL;
	}
	memcpy(pPlaintextCopy, *ppPlaintext, *pdwPlaintextSize);

	// Encrypt all the block
	__m128i PreviousBlock = { 0x00 };
	memcpy_s(&PreviousBlock, 0x10, pPlaintextCopy, 0x10);
	DWORD dwLoops = (*pdwPlaintextSize / 0x10);

	// First block use the IV
	SiEncryptBlock(&PreviousBlock, pIv, KeyScheduler, FALSE);
	memcpy_s((LPVOID)*ppCipher, *pdwPlaintextSize, &PreviousBlock, 0x10);

	// Encrypt the remaining block
	for (SIZE_T cx = 1; cx < dwLoops; cx++) {
		LPBYTE src = (LPBYTE)pPlaintextCopy + (0x10 * cx);
		LPBYTE dst = (PBYTE)*ppCipher + (0x10 * cx);

		// Get block to encrypt
		__m128i cb = { 0x00 };
		memcpy_s(&cb, 0x10, src, 0x10);

		// Encrypt block
		SiEncryptBlock(&cb, &PreviousBlock, KeyScheduler, FALSE);
		PreviousBlock = cb;

		// Copy data to the cipher
		memcpy_s(dst, *pdwPlaintextSize , &cb, 0x10);
	}

	// Free memory and return
	HeapFree(hProcessHandle, 0x00, pPlaintextCopy);
	return S_OK;
}

/**
 * @brief Encrypt string with AES-256 CBC algorithm.
 * @param ppPlaintext Pointer to the plaintext to encrypt.
 * @param pdwPlaintextSize Pointer to the size of the plaintext to encrypt.
 * @param KeyScheduler Pointer to the key scheduler
 * @param pIv Pointer to the IV.
 * @param ppCipher Pointer to the cipher.
 * @param pdwCipherSize Pointer to the size of the cipher.
 * @return Whether the string has been encrypted.
*/
_Success_(return == S_OK) _Must_inspect_impl_
HRESULT Si256EncryptString(
	_In_    PVOID *   ppPlaintext,
	_In_    PDWORD    pdwPlaintextSize,
	_In_    __m128i * KeyScheduler,
	_In_    __m128i * pIv,
	_Inout_ PVOID *   ppCipher,
	_Out_   PDWORD    pdwCipherSize
) {
	if (ppPlaintext == NULL || pdwPlaintextSize == NULL || pdwCipherSize == NULL)
		return E_INVALIDARG;

	// Get the total size for blocks
	while (*pdwPlaintextSize % 0x10 != 0x00)
		(*pdwPlaintextSize)++;
	*pdwCipherSize = *pdwPlaintextSize;

	// Allocate memory for the copy of the cipher 
	HANDLE hProcessHandle = GetProcessHeap();
	if (ppCipher == NULL)
		return E_FAIL;
	*ppCipher = HeapAlloc(hProcessHandle, HEAP_ZERO_MEMORY, *pdwPlaintextSize);

	// Allocate memory for a the padded plaintext
	PVOID pPlaintextCopy = HeapAlloc(hProcessHandle, HEAP_ZERO_MEMORY, *pdwPlaintextSize);
	if (pPlaintextCopy == NULL) {
		HeapFree(hProcessHandle, 0x00, *ppCipher);
		return E_FAIL;
	}
	memcpy(pPlaintextCopy, *ppPlaintext, *pdwPlaintextSize);

	// Encrypt all the block
	__m128i PreviousBlock = { 0x00 };
	memcpy_s(&PreviousBlock, 0x10, pPlaintextCopy, 0x10);
	DWORD dwLoops = (*pdwPlaintextSize / 0x10);

	// First block use the IV
	SiEncryptBlock(&PreviousBlock, pIv, KeyScheduler, TRUE);
	memcpy_s((LPVOID)*ppCipher, *pdwPlaintextSize, &PreviousBlock, 0x10);

	// Encrypt the remaining block
	for (SIZE_T cx = 1; cx < dwLoops; cx++) {
		LPBYTE src = (LPBYTE)pPlaintextCopy + (0x10 * cx);
		LPBYTE dst = (PBYTE)*ppCipher + (0x10 * cx);

		// Get block to encrypt
		__m128i cb = { 0x00 };
		memcpy_s(&cb, 0x10, src, 0x10);

		// Encrypt block
		SiEncryptBlock(&cb, &PreviousBlock, KeyScheduler, TRUE);
		PreviousBlock = cb;

		// Copy data to the cipher
		memcpy_s(dst, *pdwPlaintextSize, &cb, 0x10);
	}

	// Free memory and return
	HeapFree(hProcessHandle, 0x00, pPlaintextCopy);
	return S_OK;
}

/**
 * @brief Decrypt a string that has been previously encrypted with AES-128 CBC algorithm.
 * @param ppCipher Pointer to the cipher to decrypt.
 * @param pdwCipherSize Pointer to the size of the cipher to decrypt.
 * @param KeyScheduler Pointer to the key scheduler.
 * @param pIv Pointer to the IV.
 * @param pPlaintext Pointer to the plaintext.
 * @return Whether the string has been decrypted.
*/
_Success_(return == S_OK) _Must_inspect_impl_
HRESULT Si128DecryptString(
	_In_  PVOID*   ppCipher,
	_In_  PDWORD   pdwCipherSize,
	_In_  __m128i* KeyScheduler,
	_In_  __m128i* pIv,
	_Out_ PVOID*   ppPlaintext
) {
	if (ppCipher == NULL || pdwCipherSize == NULL || KeyScheduler == NULL || pIv == NULL)
		return E_INVALIDARG;

	// Allocate memory for the plaintext 
	HANDLE hProcessHandle = GetProcessHeap();
	*ppPlaintext = HeapAlloc(hProcessHandle, HEAP_ZERO_MEMORY, *pdwCipherSize);

	// Decrypt first block
	__m128i PreviousBlock = { 0x00 };
	__m128i cb = { 0x00 };
	memcpy(&cb, *ppCipher, 0x10);

	SiDecryptBlock(&cb, pIv, KeyScheduler, FALSE);
	if (ppPlaintext == NULL || *ppPlaintext == NULL)
		return E_FAIL;
	memcpy_s(*ppPlaintext, *pdwCipherSize , &cb, 0x10);

	// Decrypt remaining blocks
	for (SIZE_T cx = 1; cx < (*pdwCipherSize / 0x10); cx++) {
		LPBYTE src = (LPBYTE)*ppCipher + (0x10 * cx);
		LPBYTE dst = (LPBYTE)*ppPlaintext + (0x10 * cx);

		memcpy_s(&cb, 0x10, src, 0x10);
		memcpy_s(&PreviousBlock, 0x10, src - 0x10, 0x10);

		SiDecryptBlock(&cb, &PreviousBlock, KeyScheduler, FALSE);
		memcpy_s(dst, *pdwCipherSize, &cb, 0x10);
	}

	// Free memory and return
	HeapFree(hProcessHandle, 0x00, *ppCipher);
	return S_OK;
}

/**
 * @brief Decrypt a string that has been previously encrypted with AES-256 CBC algorithm.
 * @param ppCipher Pointer to the cipher to decrypt.
 * @param pdwCipherSize Pointer to the size of the cipher to decrypt.
 * @param KeyScheduler Pointer to the key scheduler.
 * @param pIv Pointer to the IV.
 * @param pPlaintext Pointer to the plaintext.
 * @return Whether the string has been decrypted.
*/
_Success_(return == S_OK) _Must_inspect_impl_
HRESULT Si256DecryptString(
	_In_  PVOID *   ppCipher,
	_In_  PDWORD    pdwCipherSize,
	_In_  __m128i * KeyScheduler,
	_In_  __m128i * pIv,
	_Out_ PVOID *   ppPlaintext
) {
	if (ppCipher == NULL || pdwCipherSize == NULL || KeyScheduler == NULL || pIv == NULL)
		return E_INVALIDARG;

	// Allocate memory for the plaintext 
	HANDLE hProcessHandle = GetProcessHeap();
	*ppPlaintext = HeapAlloc(hProcessHandle, HEAP_ZERO_MEMORY, *pdwCipherSize);

	// Decrypt first block
	__m128i PreviousBlock = { 0x00 };
	__m128i cb = { 0x00 };
	memcpy(&cb, *ppCipher, 0x10);

	SiDecryptBlock(&cb, pIv, KeyScheduler, TRUE);
	if (ppPlaintext == NULL || *ppPlaintext == NULL)
		return E_FAIL;
	memcpy_s(*ppPlaintext, *pdwCipherSize, &cb, 0x10);

	// Decrypt remaining blocks
	for (SIZE_T cx = 1; cx < (*pdwCipherSize / 0x10); cx++) {
		LPBYTE src = (LPBYTE)*ppCipher + (0x10 * cx);
		LPBYTE dst = (LPBYTE)*ppPlaintext + (0x10 * cx);

		memcpy_s(&cb, 0x10, src, 0x10);
		memcpy_s(&PreviousBlock, 0x10, src - 0x10, 0x10);

		SiDecryptBlock(&cb, &PreviousBlock, KeyScheduler, TRUE);
		memcpy_s(dst, *pdwCipherSize, &cb, 0x10);
	}

	// Free memory and return
	HeapFree(hProcessHandle, 0x00, *ppCipher);
	return S_OK;
}

/**
 * @brief Test AES 128 CBC encryption and decryption.
*/
HRESULT Si128BlockTest() {
	wprintf(L"[>] AES-128 CBC Block Encryption\n");

	// 1. Generate key
	__m128i m128Key = { 0x00 };
	SiGenerateRandom(&m128Key, FALSE);
	long long v[2];
	_mm_store_si128((__m128i*)v, m128Key);
	wprintf(L"[*] Key: 0x%llx 0x%llx\n", v[0], v[1]);

	// 2. Generate IV
	__m128i m128Iv = { 0x00 };
	SiGenerateRandom(&m128Iv, FALSE);
	_mm_store_si128((__m128i*)v, m128Iv);
	wprintf(L"[*] IV:  0x%llx 0x%llx\n\n", v[0], v[1]);

	// 3. Initialise encryption key scheduler
	__m128i EncryptionScheduler[11] = { 0x00 };
	Si128KeyExpansion(EncryptionScheduler, &m128Key);

	// 4. Initialise decryption key scheduler
	__m128i DecryptionScheduler[11] = { 0x00 };
	Si128InverseCipher(DecryptionScheduler, EncryptionScheduler);

	// 5. Encrypt data
	LPCWSTR wszString = L"I know that I know nothing - ipse se nihil scire id unum sciat";
	wprintf(L"[*] Pre-Encryption:\n%s\n\n", wszString);

	PVOID pCipher = NULL;
	DWORD dwStringSize = (DWORD)(wcslen(wszString) * sizeof(WCHAR));
	DWORD dwCipherSize = 0x00;

	if (FAILED(Si128EncryptString((PVOID*)&wszString, &dwStringSize, EncryptionScheduler, &m128Iv, &pCipher, &dwCipherSize)))
		return E_FAIL;

	// 6. Decrypt data
	PVOID pPLaintext = NULL;
	if (FAILED(Si128DecryptString(&pCipher, &dwCipherSize, DecryptionScheduler, &m128Iv, &pPLaintext)))
		return E_FAIL;

	// 8. Print result
	wprintf(L"[*] Post-Decryption:\n%s\n\n", (LPWSTR)pPLaintext);
	return S_OK;
}

/**
 * @brief Test AES 256 CBC encryption and decryption.
*/
HRESULT Si256BlockTest() {
	wprintf(L"[>] AES-256 CBC Block Encryption\n");

	// 1. Generate key
	__m256i m256Key = { 0x00 };
	SiGenerateRandom(&m256Key, TRUE);

	long long v[4];
	_mm256_store_si256((__m256i*)v, m256Key);
	wprintf(L"[*] Key: 0x%llx 0x%llx 0x%llx 0x%llx\n", v[0], v[1], v[2], v[3]);

	// 2. Generate IV
	__m128i m128Iv = { 0x00 };
	SiGenerateRandom(&m128Iv, FALSE);
	_mm_store_si128((__m128i*)v, m128Iv);
	wprintf(L"[*] IV:  0x%llx 0x%llx\n\n", v[0], v[1]);

	// 3. Initialise encryption key scheduler
	__m128i EncryptionScheduler[15] = { 0x00 };
	Si256KeyExpansion(EncryptionScheduler, &m256Key);

	// 4. Initialise decryption key scheduler
	__m128i DecryptionScheduler[15] = { 0x00 };
	Si256InverseCipher(DecryptionScheduler, EncryptionScheduler);

	// 5. Encrypt data
	LPCWSTR wszString = L"I know that I know nothing - ipse se nihil scire id unum sciat";
	wprintf(L"[*] Pre-Encryption:\n%s\n\n", wszString);

	PVOID pCipher = NULL;
	DWORD dwStringSize = (DWORD)(wcslen(wszString) * sizeof(WCHAR));
	DWORD dwCipherSize = dwStringSize;

	if (FAILED(Si256EncryptString((PVOID*)&wszString, &dwStringSize, EncryptionScheduler, &m128Iv, &pCipher, &dwCipherSize)))
		return E_FAIL;

	// 6. Decrypt data
	PVOID pPLaintext = NULL;
	if (FAILED(Si256DecryptString(&pCipher, &dwCipherSize, DecryptionScheduler, &m128Iv, &pPLaintext)))
		return E_FAIL;

	// 8. Print result
	wprintf(L"[*] Post-Decryption:\n%s\n\n", (LPWSTR)pPLaintext);
	return S_OK;
}

int main() {
	wprintf(L"---------------------------------------------------------------------------------\n");
	wprintf(L" AES-128 and AES-256 CBC Encryption and Decryption using AES-NI instruction set\n");
	wprintf(L"                      Copyright (C) Paul L. (@am0nsec)\n");
	wprintf(L"---------------------------------------------------------------------------------\n\n");

	// Check whether the AES-NI instruction set is enabled.
	if (!SiIsAESNIEnabled())
		return EXIT_FAILURE;

	if (FAILED(Si128BlockTest()))
		return EXIT_FAILURE;
	if (FAILED(Si256BlockTest()))
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
