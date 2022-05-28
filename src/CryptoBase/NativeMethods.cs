using System.Runtime.Intrinsics.Arm;

namespace CryptoBase;

public static class NativeMethods
{
	private const string DllName = @"cryptobase_native";

	public static bool IsSupportRustNative
	{
		get
		{
			if (OperatingSystem.IsWindows() && (X86Base.IsSupported || X86Base.X64.IsSupported || ArmBase.Arm64.IsSupported))
			{
				return true;
			}

			if (OperatingSystem.IsLinux() && (X86Base.X64.IsSupported || ArmBase.Arm64.IsSupported || ArmBase.IsSupported))
			{
				return true;
			}

			if (OperatingSystem.IsMacOS() && (X86Base.X64.IsSupported || ArmBase.Arm64.IsSupported))
			{
				return true;
			}

			return false;
		}
	}

	#region MD5

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern nuint md5_new();

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void md5_dispose(nuint ptr);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void md5_reset(nuint ptr);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void md5_update_final(nuint ptr, nuint input, nuint inputSize, nuint output, nuint outputSize);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void md5_update(nuint ptr, nuint input, nuint inputSize);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void md5_get_hash(nuint ptr, nuint output, nuint outputSize);

	#endregion

	#region SM3

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern nuint sm3_new();

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sm3_dispose(nuint ptr);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sm3_reset(nuint ptr);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sm3_update_final(nuint ptr, nuint input, nuint inputSize, nuint output, nuint outputSize);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sm3_update(nuint ptr, nuint input, nuint inputSize);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sm3_get_hash(nuint ptr, nuint output, nuint outputSize);

	#endregion

	#region SHA1

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern nuint sha1_new();

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha1_dispose(nuint ptr);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha1_reset(nuint ptr);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha1_update_final(nuint ptr, nuint input, nuint inputSize, nuint output, nuint outputSize);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha1_update(nuint ptr, nuint input, nuint inputSize);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha1_get_hash(nuint ptr, nuint output, nuint outputSize);

	#endregion

	#region SHA224

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern nuint sha224_new();

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha224_dispose(nuint ptr);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha224_reset(nuint ptr);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha224_update_final(nuint ptr, nuint input, nuint inputSize, nuint output, nuint outputSize);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha224_update(nuint ptr, nuint input, nuint inputSize);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha224_get_hash(nuint ptr, nuint output, nuint outputSize);

	#endregion

	#region SHA256

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern nuint sha256_new();

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha256_dispose(nuint ptr);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha256_reset(nuint ptr);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha256_update_final(nuint ptr, nuint input, nuint inputSize, nuint output, nuint outputSize);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha256_update(nuint ptr, nuint input, nuint inputSize);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha256_get_hash(nuint ptr, nuint output, nuint outputSize);

	#endregion

	#region SHA384

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern nuint sha384_new();

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha384_dispose(nuint ptr);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha384_reset(nuint ptr);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha384_update_final(nuint ptr, nuint input, nuint inputSize, nuint output, nuint outputSize);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha384_update(nuint ptr, nuint input, nuint inputSize);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha384_get_hash(nuint ptr, nuint output, nuint outputSize);

	#endregion

	#region SHA512

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern nuint sha512_new();

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha512_dispose(nuint ptr);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha512_reset(nuint ptr);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha512_update_final(nuint ptr, nuint input, nuint inputSize, nuint output, nuint outputSize);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha512_update(nuint ptr, nuint input, nuint inputSize);

	[DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
	[SuppressGCTransition]
	internal static extern void sha512_get_hash(nuint ptr, nuint output, nuint outputSize);

	#endregion
}
