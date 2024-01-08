namespace CryptoBase;

public static partial class NativeMethods
{
	private const string DllName = @"cryptobase_native";

	public static bool IsSupportRustNative
	{
		get
		{
			if (OperatingSystem.IsWindows() && RuntimeInformation.ProcessArchitecture is Architecture.X86 or Architecture.X64 or Architecture.Arm64)
			{
				return true;
			}

			if (OperatingSystem.IsLinux() && RuntimeInformation.ProcessArchitecture is Architecture.X64 or Architecture.Arm64 or Architecture.Arm)
			{
				return true;
			}

			if (OperatingSystem.IsMacOS() && RuntimeInformation.ProcessArchitecture is Architecture.X64 or Architecture.Arm64)
			{
				return true;
			}

			return false;
		}
	}

	#region MD5

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial nuint md5_new();

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void md5_dispose(nuint ptr);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void md5_reset(nuint ptr);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void md5_update_final(nuint ptr, nuint input, nuint inputSize, nuint output, nuint outputSize);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void md5_update(nuint ptr, nuint input, nuint inputSize);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void md5_get_hash(nuint ptr, nuint output, nuint outputSize);

	#endregion

	#region SM3

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial nuint sm3_new();

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sm3_dispose(nuint ptr);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sm3_reset(nuint ptr);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sm3_update_final(nuint ptr, nuint input, nuint inputSize, nuint output, nuint outputSize);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sm3_update(nuint ptr, nuint input, nuint inputSize);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sm3_get_hash(nuint ptr, nuint output, nuint outputSize);

	#endregion

	#region SHA1

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial nuint sha1_new();

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha1_dispose(nuint ptr);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha1_reset(nuint ptr);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha1_update_final(nuint ptr, nuint input, nuint inputSize, nuint output, nuint outputSize);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha1_update(nuint ptr, nuint input, nuint inputSize);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha1_get_hash(nuint ptr, nuint output, nuint outputSize);

	#endregion

	#region SHA224

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial nuint sha224_new();

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha224_dispose(nuint ptr);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha224_reset(nuint ptr);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha224_update_final(nuint ptr, nuint input, nuint inputSize, nuint output, nuint outputSize);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha224_update(nuint ptr, nuint input, nuint inputSize);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha224_get_hash(nuint ptr, nuint output, nuint outputSize);

	#endregion

	#region SHA256

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial nuint sha256_new();

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha256_dispose(nuint ptr);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha256_reset(nuint ptr);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha256_update_final(nuint ptr, nuint input, nuint inputSize, nuint output, nuint outputSize);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha256_update(nuint ptr, nuint input, nuint inputSize);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha256_get_hash(nuint ptr, nuint output, nuint outputSize);

	#endregion

	#region SHA384

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial nuint sha384_new();

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha384_dispose(nuint ptr);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha384_reset(nuint ptr);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha384_update_final(nuint ptr, nuint input, nuint inputSize, nuint output, nuint outputSize);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha384_update(nuint ptr, nuint input, nuint inputSize);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha384_get_hash(nuint ptr, nuint output, nuint outputSize);

	#endregion

	#region SHA512

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial nuint sha512_new();

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha512_dispose(nuint ptr);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha512_reset(nuint ptr);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha512_update_final(nuint ptr, nuint input, nuint inputSize, nuint output, nuint outputSize);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha512_update(nuint ptr, nuint input, nuint inputSize);

	[LibraryImport(DllName)]
	[SuppressGCTransition]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl), typeof(CallConvSuppressGCTransition)])]
	internal static partial void sha512_get_hash(nuint ptr, nuint output, nuint outputSize);

	#endregion
}
