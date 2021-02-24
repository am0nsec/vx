/**
* @file        silverhand.h
* @date        23-02-2021
* @author      Paul L. (@am0nsec)
* @version     1.0
* @brief       AES-128 and AES-256 CBC Encryption and Decryption using AES-NI instruction set.
* @details
* @link        https://github.com/am0nsec/vx
* @copyright   This project has been released under the GNU Public License v3 license.
*/
#ifndef __SILVERHAND_H_GUARD__
#define __SILVERHAND_H_GUARD__
#include <Windows.h>   // Windows API
#include <immintrin.h> // SSE2 intrinsics

/**
 * @brief Check whether AES-IN instruction set is available.
 * @return Whether AES-IN instruction set is available.
*/
_Success_(return == S_OK) _Must_inspect_impl_
BOOL __stdcall SiIsAESNIEnabled();

/**
 * @brief Generate either 128 or 256 bits of random data.
 * @param pData Pointer to a 256-bits or 128-bits variable.
*/
VOID __stdcall SiGenerateRandom(
	_Inout_ LPVOID pData,
	_In_    BOOL   b256
);

/**
 * @brief Initialise Key Scheduler for the rounds of encryption.
 * @param KeyScheduler Pointer to the encryption key scheduler.
 * @param Key Pointer to the 128-bits key.
*/
VOID __stdcall Si128KeyExpansion(
	_Out_ __m128i * KeyScheduler,
	_In_  __m128i * Key
);

/**
 * @brief Initialise Key Scheduler for the rounds of encryption.
 * @param KeyScheduler Pointer to the encryption key scheduler.
 * @param Key Pointer to the 256-bits key.
*/
VOID __stdcall Si256KeyExpansion(
	_Out_ __m128i * KeyScheduler,
	_In_  __m256i * Key
);

/**
 * @brief Initialise Key Scheduler for the rounds of encryptions.
 * @param DecryptionkeyScheduler Pointer to the decryption key scheduler.
 * @param EncryptionKeyScheduler Pointer to the encryption key scheduler.
*/
VOID __stdcall Si128InverseCipher(
	_Out_ __m128i * DecryptionkeyScheduler,
	_In_  __m128i * EncryptionKeyScheduler
);

/**
 * @brief Initialise Key Scheduler for the rounds of encryptions.
 * @param DecryptionkeyScheduler Pointer to the decryption key scheduler.
 * @param EncryptionKeyScheduler Pointer to the encryption key scheduler.
*/
VOID __stdcall Si256InverseCipher(
	_Out_ __m128i * DecryptionkeyScheduler,
	_In_  __m128i * EncryptionKeyScheduler
);

/**
 * @brief AES-128 and AES-256 CBC mode encryption of a single block
 * @param Block Pointer to the 128-bits of data to encrypt.
 * @param PreviousBlock Pointer to the 128-bits of the previously encrypted data.
 * @param KeyScheduler Pointer to the 128 key scheduler.
 * @param bAES256 Whether this is AES-128 (default) or AES-256.
*/
VOID __stdcall SiEncryptBlock(
	_Inout_ __m128i * Block,
	_In_    __m128i * PreviousBlock,
	_In_    __m128i * KeyScheduler,
	_In_    BOOL      bAES256
);

/**
 * @brief AES-128 and AES-256 CBC mode decryption of a single block
 * @param Block Pointer to the 128-bits of data to decrypt.
 * @param PreviousBlock Pointer to the 128-bits of the previously decrypted data.
 * @param KeyScheduler Pointer to the decryption key scheduler.
 * @param bAES256 Whether this is AES-128 (default) or AES-256.
*/
VOID __stdcall SiDecryptBlock(
	_Inout_ __m128i* Block,
	_In_    __m128i* PreviousBlock,
	_In_    __m128i* KeyScheduler,
	_In_    BOOL     bAES256
);

#endif // !__SILVERHAND_H_GUARD__
