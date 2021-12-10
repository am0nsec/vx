using System;
using System.Linq;
using System.Text;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;



namespace VX {

    /// <summary>
    /// __m128 intrinsic vector type.
    /// </summary>
    [StructLayout(LayoutKind.Explicit, Pack = 16)]
    public struct __m128i {
        [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst = 16)]
        [FieldOffset(0)]
        public sbyte[] m128i_i8;

        [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst = 8)]
        [FieldOffset(0)]
        public short[] m128i_i16;

        [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst = 4)]
        [FieldOffset(0)]
        public int[] m128i_i32;

        [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst = 2)]
        [FieldOffset(0)]
        public long[] m128i_i64;

        [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst = 16)]
        [FieldOffset(0)]
        public byte[] m128i_u8;

        [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst = 8)]
        [FieldOffset(0)]
        public ushort[] m128i_u16;

        [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst = 4)]
        [FieldOffset(0)]
        public uint[] m128i_u32;

        [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst = 2)]
        [FieldOffset(0)]
        public ulong[] m128i_u64;
    }

    /// <summary>
    /// Pseudo-structure for keeping the Marshaller happy ¯\_(ツ)_/¯
    /// </summary>
    [StructLayout(LayoutKind.Explicit, Pack = 16)]
    public struct KeyExpension {
        [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst = 11)]
        [FieldOffset(0)]
        public __m128i[] v;
    }

    /// <summary>
    /// Pseudo-structure for keeping the Marshaller happy ¯\_(ツ)_/¯
    /// </summary>
    [StructLayout(LayoutKind.Explicit, Pack = 16)]
    public struct DecryptionScheduler {
        [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst = 11)]
        [FieldOffset(0)]
        public __m128i[] v;
    }

    public class AVXAES : ASMLoader {

        /// <summary>
        /// Generate either 128 or 256 bits of random data.
        /// </summary>
        /// <param name="pData">pData Pointer to a 256-bits or 128-bits variable.</param>
        /// <param name="b256">Whether 256 bits of random data has to be generated.</param>
        private delegate void TSiGenerateRandom(
            IntPtr pData,
            bool b256
        );

        /// <summary>
        /// Initialise Key Scheduler for the rounds of encryption.
        /// </summary>
        /// <param name="KeyScheduler">Pointer to the encryption key scheduler.</param>
        /// <param name="Key">Pointer to the 128-bits key.</param>
        private delegate void TSi128KeyExpansion(
            IntPtr KeyScheduler,
            IntPtr Key
        );

        /// <summary>
        /// Initialise Key Scheduler for the rounds of encryptions.
        /// </summary>
        /// <param name="KeyScheduler">Pointer to the decryption key scheduler.</param>
        /// <param name="Key">Pointer to the encryption key scheduler.</param>
        private delegate void TSi128InverseCipher(
            IntPtr DecryptionkeyScheduler,
            IntPtr EncryptionKeyScheduler
        );

        /// <summary>
        /// AES-128 and AES-256 CBC mode encryption of a single block.
        /// </summary>
        /// <param name="Block">Pointer to the 128-bits of data to encrypt.</param>
        /// <param name="PreviousBlock">Pointer to the 128-bits of the previously encrypted data.</param>
        /// <param name="KeyScheduler">Pointer to the 128 key scheduler.</param>
        /// <param name="bAES256">Whether this is AES-128 (default) or AES-256.</param>
        private delegate void TSiEncryptBlock(
            IntPtr Block,
            IntPtr PreviousBlock,
            IntPtr KeyScheduler,
            bool bAES256
        );

        /// <summary>
        /// AES-128 and AES-256 CBC mode decryption of a single block.
        /// </summary>
        /// <param name="Block">AES-128 and AES-256 CBC mode decryption of a single block.</param>
        /// <param name="PreviousBlock">Pointer to the 128-bits of the previously decrypted data.</param>
        /// <param name="KeyScheduler">Pointer to the decryption key scheduler.</param>
        /// <param name="bAES256">Pointer to the decryption key scheduler.</param>
        private delegate void TSiDecryptBlock(
            IntPtr Block,
            IntPtr PreviousBlock,
            IntPtr KeyScheduler,
            bool bAES256
        );

        // Simply assembled the ASM code from the following repository: https://github.com/am0nsec/vx/blob/master/Win64.VirTool.Crypt.Silverhand/SILVERHAND.ASM
        //
        // .text:
        // #include <Windows.h>
        // #include <stdio.h>
        //
        // extern void SiStartBlock();
        // extern void SiIsAESNIEnabled();
        // extern void SiGenerateRandom();
        // extern void Si128KeyExpansion();
        // extern void Si256KeyExpansion();
        // extern void Si128InverseCipher();
        // extern void Si256InverseCipher();
        // extern void SiEncryptBlock();
        // extern void SiDecryptBlock();
        // extern void SiEndBlock();
        //
        // int main() {
        //      LPBYTE ip = &SiStartBlock;
        //      
        //      printf("// SiIsAESNIEnabled   0x%08llx\n", (LPBYTE)&SiIsAESNIEnabled - ip);
        //      printf("// SiGenerateRandom   0x%08llx\n", (LPBYTE)&SiGenerateRandom - ip);
        //      printf("// Si128KeyExpansion  0x%08llx\n", (LPBYTE)&Si128KeyExpansion - ip);
        //      printf("// Si256KeyExpansion  0x%08llx\n", (LPBYTE)&Si256KeyExpansion - ip);
        //      printf("// Si128InverseCipher 0x%08llx\n", (LPBYTE)&Si128InverseCipher - ip);
        //      printf("// Si256InverseCipher 0x%08llx\n", (LPBYTE)&Si256InverseCipher - ip);
        //      printf("// SiEncryptBlock     0x%08llx\n", (LPBYTE)&SiEncryptBlock - ip);
        //      printf("// SiDecryptBlock     0x%08llx\n", (LPBYTE)&SiDecryptBlock - ip);
        //      printf("\n\n\n");
        //
        //      DWORD cx = 0x00;
        //      printf("byte[] asm = new byte[] {");
        //      do {
        //          printf("0x%02x, ", (unsigned char)*ip); cx++
        //      } while (ip++ != SiEndBlock);
        //
        //      printf("};\n\nint NumberOfBytes = 0x%llx;", cx);
        //      return 0x00;
        // }
        private byte[] SilverhandCode { get; } = new byte[] { 0x33, 0xc9, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0xa2, 0x81, 0xe1, 0x00, 0x00, 0x00, 0x02, 0x81, 0xf9, 0x00, 0x00, 0x00, 0x02, 0x75, 0x06, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x33, 0xc0, 0xc3, 0x51, 0x48, 0x8b, 0xc1, 0x80, 0xfa, 0x01, 0x74, 0x07, 0xb9, 0x02, 0x00, 0x00, 0x00, 0xeb, 0x05, 0xb9, 0x04, 0x00, 0x00, 0x00, 0x48, 0x0f, 0xc7, 0xf3, 0x48, 0x89, 0x18, 0x48, 0x83, 0xc0, 0x08, 0xe2, 0xf3, 0x59, 0xc3, 0x48, 0x8b, 0xd9, 0xf3, 0x0f, 0x6f, 0x02, 0xf3, 0x0f, 0x7f, 0x03, 0x48, 0x83, 0xc3, 0x10, 0xb9, 0x0a, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x3a, 0xdf, 0xc8, 0x08, 0x66, 0x0f, 0x70, 0xc9, 0xff, 0xc5, 0xe9, 0x73, 0xf8, 0x04, 0x66, 0x0f, 0xef, 0xc2, 0xc5, 0xe9, 0x73, 0xf8, 0x04, 0x66, 0x0f, 0xef, 0xc2, 0xc5, 0xe9, 0x73, 0xf8, 0x04, 0x66, 0x0f, 0xef, 0xc2, 0x66, 0x0f, 0xef, 0xc1, 0xf3, 0x0f, 0x7f, 0x03, 0x48, 0x83, 0xc3, 0x10, 0xe2, 0xcc, 0xc3, 0x48, 0x8b, 0xc1, 0xf3, 0x0f, 0x6f, 0x0a, 0x66, 0x0f, 0x7f, 0x08, 0xf3, 0x0f, 0x6f, 0x5a, 0x10, 0x66, 0x0f, 0x7f, 0x58, 0x10, 0xb9, 0x0d, 0x00, 0x00, 0x00, 0x48, 0x33, 0xdb, 0x80, 0xfb, 0x00, 0x74, 0x00, 0x66, 0x0f, 0x3a, 0xdf, 0xd3, 0x40, 0x66, 0x0f, 0x70, 0xd2, 0xff, 0x66, 0x0f, 0x6f, 0xe1, 0x66, 0x0f, 0x73, 0xfc, 0x04, 0x66, 0x0f, 0xef, 0xcc, 0x66, 0x0f, 0x73, 0xfc, 0x04, 0x66, 0x0f, 0xef, 0xcc, 0x66, 0x0f, 0x73, 0xfc, 0x04, 0x66, 0x0f, 0xef, 0xcc, 0x66, 0x0f, 0xef, 0xca, 0x66, 0x0f, 0x7f, 0x08, 0xff, 0xc3, 0xeb, 0x34, 0x66, 0x0f, 0x3a, 0xdf, 0xd1, 0x00, 0x66, 0x0f, 0x70, 0xd2, 0xaa, 0x66, 0x0f, 0x6f, 0xe3, 0x66, 0x0f, 0x73, 0xfc, 0x04, 0x66, 0x0f, 0xef, 0xdc, 0x66, 0x0f, 0x73, 0xfc, 0x04, 0x66, 0x0f, 0xef, 0xdc, 0x66, 0x0f, 0x73, 0xfc, 0x04, 0x66, 0x0f, 0xef, 0xdc, 0x66, 0x0f, 0xef, 0xda, 0x66, 0x0f, 0x7f, 0x18, 0xff, 0xcb, 0x48, 0x83, 0xc0, 0x10, 0xe2, 0x8b, 0xc3, 0x51, 0x52, 0xf3, 0x0f, 0x6f, 0x01, 0xf3, 0x0f, 0x6f, 0x0a, 0xf3, 0x0f, 0x7f, 0x09, 0x48, 0x83, 0xc1, 0x10, 0x48, 0x83, 0xc2, 0x10, 0xbb, 0x09, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x38, 0xdb, 0x0a, 0xf3, 0x0f, 0x7f, 0x09, 0x48, 0x83, 0xc1, 0x10, 0x48, 0x83, 0xc2, 0x10, 0xff, 0xcb, 0x75, 0xeb, 0xf3, 0x0f, 0x6f, 0x0a, 0xf3, 0x0f, 0x7f, 0x09, 0x5a, 0x59, 0xc3, 0x51, 0x52, 0x50, 0x48, 0x8b, 0xc1, 0xf3, 0x0f, 0x6f, 0x0a, 0xf3, 0x0f, 0x7f, 0x08, 0x48, 0x83, 0xc0, 0x10, 0x48, 0x83, 0xc2, 0x10, 0xb9, 0x0d, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x38, 0xdb, 0x0a, 0xf3, 0x0f, 0x7f, 0x08, 0x48, 0x83, 0xc0, 0x10, 0x48, 0x83, 0xc2, 0x10, 0xe2, 0xed, 0xf3, 0x0f, 0x6f, 0x0a, 0xf3, 0x0f, 0x7f, 0x08, 0x58, 0x5a, 0x59, 0xc3, 0x41, 0x50, 0x48, 0x8b, 0xc1, 0xf3, 0x0f, 0x6f, 0x00, 0x66, 0x0f, 0xef, 0x02, 0x41, 0x80, 0xf9, 0x01, 0x74, 0x07, 0xb9, 0x09, 0x00, 0x00, 0x00, 0xeb, 0x05, 0xb9, 0x0d, 0x00, 0x00, 0x00, 0x66, 0x41, 0x0f, 0xef, 0x00, 0x49, 0x83, 0xc0, 0x10, 0x66, 0x41, 0x0f, 0x38, 0xdc, 0x00, 0x49, 0x83, 0xc0, 0x10, 0xe2, 0xf4, 0x66, 0x41, 0x0f, 0x38, 0xdd, 0x00, 0xf3, 0x0f, 0x7f, 0x00, 0x41, 0x58, 0xc3, 0x41, 0x50, 0x48, 0x8b, 0xc1, 0xf3, 0x0f, 0x6f, 0x00, 0x41, 0x80, 0xf9, 0x01, 0x74, 0x0e, 0x49, 0x81, 0xc0, 0xa0, 0x00, 0x00, 0x00, 0xb9, 0x09, 0x00, 0x00, 0x00, 0xeb, 0x0c, 0x49, 0x81, 0xc0, 0xe0, 0x00, 0x00, 0x00, 0xb9, 0x0d, 0x00, 0x00, 0x00, 0x66, 0x41, 0x0f, 0xef, 0x00, 0x49, 0x83, 0xe8, 0x10, 0x66, 0x41, 0x0f, 0x38, 0xde, 0x00, 0x49, 0x83, 0xe8, 0x10, 0xe2, 0xf4, 0x66, 0x41, 0x0f, 0x38, 0xdf, 0x00, 0x66, 0x0f, 0xef, 0x02, 0x41, 0x58, 0xf3, 0x0f, 0x7f, 0x00, 0xc3, 0xcc };

        private TSiGenerateRandom SiGenerateRandom { get; set; } = null;
        private TSi128KeyExpansion Si128KeyExpansion { get; set; } = null;
        private TSi128InverseCipher Si128InverseCipher { get; set; } = null;
        private TSiEncryptBlock SiEncryptBlock { get; set; } = null;
        private TSiDecryptBlock SiDecryptBlock { get; set; } = null;

        /// <summary>
        /// Pointer to the encryption/decryption key.
        /// </summary>
        public IntPtr pKey { get; private set; } = IntPtr.Zero;

        /// <summary>
        /// Pointer to the initialisation vector.
        /// </summary>
        public IntPtr pIv { get; private set; } = IntPtr.Zero;

        /// <summary>
        /// Pointer to the encryption key scheduler.
        /// </summary>
        private IntPtr pEncryptionScheduler { get; set; } = IntPtr.Zero;

        /// <summary>
        /// Pointer to the decryption key scheduler.
        /// </summary>
        private IntPtr pDecryptionScheduler { get; set; } = IntPtr.Zero;

        /// <summary>
        /// Initialise the ASM loader.
        /// </summary>
        /// <param name="Key">Nullable encryption/decryption key</param>
        /// <param name="Iv">Nullable initialisation vector.</param>
        public void Initialise(
            __m128i? Key,
            __m128i? Iv
        ) {
            base.Initialise(SilverhandCode);

            // SiIsAESNIEnabled   0x00000000
            // SiGenerateRandom   0x00000020
            // Si128KeyExpansion  0x00000044
            // Si256KeyExpansion  0x0000008d
            // Si128InverseCipher 0x00000120
            // Si256InverseCipher 0x0000015b
            // SiEncryptBlock     0x00000195
            // SiDecryptBlock     0x000001d6
            SiGenerateRandom =   base.GetFunctionDelegate<TSiGenerateRandom>(0x00000020);
            Si128KeyExpansion =  base.GetFunctionDelegate<TSi128KeyExpansion>(0x00000044);
            Si128InverseCipher = base.GetFunctionDelegate<TSi128InverseCipher>(0x00000120);
            SiEncryptBlock =     base.GetFunctionDelegate<TSiEncryptBlock>(0x00000195);
            SiDecryptBlock =     base.GetFunctionDelegate<TSiDecryptBlock>(0x000001d6);

            // Copy or generate new key nad IV
            this.pKey = Marshal.AllocHGlobal(Marshal.SizeOf<__m128i>());
            if (Key != null) {
                Marshal.StructureToPtr<__m128i?>(Key, this.pKey, false);
            } else {
                this.SiGenerateRandom(this.pKey, false);
            }

            this.pIv = Marshal.AllocHGlobal(Marshal.SizeOf<__m128i>());
            if (Iv != null) {
                Marshal.StructureToPtr<__m128i?>(Iv, this.pIv, false);
            } else {
                this.SiGenerateRandom(this.pIv, false);
            }

            // Initialise encryption key scheduler
            this.pEncryptionScheduler = Marshal.AllocHGlobal(Marshal.SizeOf<KeyExpension>());
            Si128KeyExpansion(this.pEncryptionScheduler, this.pKey);

            // Initialise decryption key scheduler
            this.pDecryptionScheduler = Marshal.AllocHGlobal(Marshal.SizeOf<DecryptionScheduler>());
            Si128InverseCipher(this.pDecryptionScheduler, this.pEncryptionScheduler);
        }

        /// <summary>
        /// Encrypt a blob of data.
        /// </summary>
        /// <param name="Blob">Array of data to encrypt.</param>
        /// <param name="BlobSize">Size of the array of data to encrypt.</param>
        /// <param name="Cipher"></param>
        /// <returns></returns>
        public bool EncryptBlob(
            byte[] Blob,
            ulong BlobSize,
            ref byte[] Cipher
        ) {
            // Make sure we have the padding correctly
            while (BlobSize % 0x10 != 0x00) {
                BlobSize++;
            }
            ulong Loops = BlobSize / 0x10;
            Cipher = new byte[BlobSize];
            Array.Resize(ref Blob, (int)BlobSize);

            // First block with the IV
            IntPtr PB = Marshal.AllocHGlobal(Marshal.SizeOf<__m128i>());
            Marshal.Copy(Blob, 0x00, PB, 0x10);

            SiEncryptBlock(PB, this.pIv, this.pEncryptionScheduler, false);
            Marshal.Copy(PB, Cipher, 0, 0x10);

            // Loop through the remaining blocks
            for (ulong cx = 0x01; cx < Loops; cx++) {
                IntPtr CB = Marshal.AllocHGlobal(Marshal.SizeOf<__m128i>());
                Marshal.Copy(Blob, (int)(0x10 * cx), CB, 0x10);

                // Encrypt block
                SiEncryptBlock(CB, PB, this.pEncryptionScheduler, false);
                Marshal.Copy(CB, Cipher, (int)(0x10 * cx), 0x10);
                PB = CB;
            }

            return true;
        }

        /// <summary>
        /// Decrypt a blob of data.
        /// </summary>
        /// <param name="Blob">Array of data to decrypt.</param>
        /// <param name="BlobSize">Size of the array of data to decrypt.</param>
        /// <param name="Plaintext">Pointer to the decrypted data.</param>
        /// <returns></returns>
        public bool DecryptBlob(
            byte[] Blob,
            ulong BlobSize,
            ref byte[] Plaintext
        ) {
            // Make sure we have enough memory
            Array.Resize(ref Plaintext, (int)BlobSize);

            // Decrypt first block
            IntPtr PB = Marshal.AllocHGlobal(Marshal.SizeOf<__m128i>());
            IntPtr CB = Marshal.AllocHGlobal(Marshal.SizeOf<__m128i>());
            Marshal.Copy(Blob, 0x00, CB, 0x10);
            SiDecryptBlock(CB, this.pIv, this.pDecryptionScheduler, false);
            Marshal.Copy(CB, Plaintext, 0x00, 0x10);

            for (ulong cx = 0x01; cx < (BlobSize / 0x10); cx++) {
                Marshal.Copy(Blob, (int)(0x10 * cx), CB, 0x10);
                Marshal.Copy(Blob, (int)((0x10 * cx) - 0x10), PB, 0x10);

                // Decrypt block
                SiDecryptBlock(CB, PB, this.pDecryptionScheduler, false);
                Marshal.Copy(CB, Plaintext, (int)(0x10 * cx), 0x10);
            }

            return true;
        }

        /// <summary>
        /// Cleanup.
        /// </summary>
        public void Uninitialise() {
            if (this.pKey != IntPtr.Zero)
                Marshal.FreeHGlobal(this.pKey);
            if (this.pIv != IntPtr.Zero)
                Marshal.FreeHGlobal(this.pIv);
            if (this.pDecryptionScheduler != IntPtr.Zero)
                Marshal.FreeHGlobal(this.pDecryptionScheduler);
            if (this.pEncryptionScheduler != IntPtr.Zero)
                Marshal.FreeHGlobal(this.pEncryptionScheduler);

            base.Uninitialise();
        }
    }


    /// <summary>
    /// Minimalistic ASM Loader. 
    /// </summary>
    public class ASMLoader {

        private MemoryMappedFile MemoryMap { get; set; }
        private MemoryMappedViewAccessor MemoryMapAccessor { get; set; }

        /// <summary>
        /// .dtor()
        /// </summary>
        ~ASMLoader() {
            this.Uninitialise();
        }

        /// <summary>
        /// Initialise the library by allocating RWX memory.
        /// </summary>
        /// <param name="asm">ASM code to load into a RWX memory page.</param>
        /// <returns></returns>
        public bool Initialise(byte[] asm) {
            // 1. Generate writable memory.
            this.MemoryMap = MemoryMappedFile.CreateNew(null, asm.Length, MemoryMappedFileAccess.ReadWriteExecute);
            this.MemoryMapAccessor = this.MemoryMap.CreateViewAccessor(0, asm.Length, MemoryMappedFileAccess.ReadWriteExecute);

            // 2. Get address of the memory region
            IntPtr RWXRegionAddressPtr = MemoryMapAccessor.SafeMemoryMappedViewHandle.DangerousGetHandle();

            // 3. Inject code
            Marshal.Copy(asm.ToArray(), 0, RWXRegionAddressPtr, asm.Length);
            return true;
        }

        /// <summary>
        /// Dispose all the disposable components.
        /// </summary>
        public void Uninitialise() {
            this.MemoryMapAccessor.Dispose();
            this.MemoryMap.Dispose();
        }

        /// <summary>
        /// Get a function pointer based on a memory displacement.
        /// </summary>
        /// <typeparam name="T">Delegate function pointer.</typeparam>
        /// <returns>A delegate based on the displacement</returns>
        public T GetFunctionDelegate<T>(ulong Displacement) where T : Delegate =>
            Marshal.GetDelegateForFunctionPointer<T>((IntPtr)((ulong)MemoryMapAccessor.SafeMemoryMappedViewHandle.DangerousGetHandle() + Displacement));
    }
}

public class Test {

    static void Main(string[] args) {

        VX.AVXAES aes = new VX.AVXAES();
        aes.Initialise(null, null);

        // 1. Local variables
        byte[] Plaintext = Encoding.UTF8.GetBytes("Amat victoria curam - cum lux abest, tenebrae vicunt - canis majoris");
        byte[] Cipher = new byte[] { };
        byte[] Decrypted = new byte[] { };

        // 2. Encrypt and decrypt
        aes.EncryptBlob(
            Plaintext,
            (ulong)Plaintext.Length,
            ref Cipher
        );
        aes.DecryptBlob(
            Cipher,
            (ulong)Cipher.Length,
            ref Decrypted
        );

        // 3. Print the result
        Console.WriteLine("Plaintext sample: " + Encoding.UTF8.GetString(Plaintext));
        Console.WriteLine("Encrypted sample: " + Convert.ToBase64String(Cipher));
        Console.WriteLine("Decrypted sample: " + Encoding.UTF8.GetString(Decrypted));

        // Cleanup.
        aes.Uninitialise();
    }
}
