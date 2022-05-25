using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase;

internal static partial class IntrinsicsUtils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<byte> Xor(this Vector128<byte> a, Vector128<byte> b)
	{
		return Sse2.Xor(a, b);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> Add(this Vector128<ulong> a, Vector128<ulong> b)
	{
		return Sse2.Add(a, b);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<byte> Xor(this Vector256<byte> a, Vector256<byte> b)
	{
		return Avx2.Xor(a, b);
	}
}
