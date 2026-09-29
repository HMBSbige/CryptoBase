namespace CryptoBase.Internal;

internal static class BlockXor
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void XorStore1(ref byte input, ref byte output, nuint offset, ref Vector128<byte> value)
	{
		value ^= Vector128.LoadUnsafe(ref input, offset);
		value.StoreUnsafe(ref output, offset);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void XorStore2(ref byte input, ref byte output, nuint offset, ref Vector128<byte> v0, ref Vector128<byte> v1)
	{
		v0 ^= Vector128.LoadUnsafe(ref input, offset);
		v0.StoreUnsafe(ref output, offset);
		v1 ^= Vector128.LoadUnsafe(ref input, offset + 16);
		v1.StoreUnsafe(ref output, offset + 16);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void XorStore4(ref byte input, ref byte output, nuint offset, ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3)
	{
		v0 ^= Vector128.LoadUnsafe(ref input, offset);
		v0.StoreUnsafe(ref output, offset);
		v1 ^= Vector128.LoadUnsafe(ref input, offset + 16);
		v1.StoreUnsafe(ref output, offset + 16);
		v2 ^= Vector128.LoadUnsafe(ref input, offset + 32);
		v2.StoreUnsafe(ref output, offset + 32);
		v3 ^= Vector128.LoadUnsafe(ref input, offset + 48);
		v3.StoreUnsafe(ref output, offset + 48);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void XorStore8(ref byte input, ref byte output, nuint offset, ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7)
	{
		v0 ^= Vector128.LoadUnsafe(ref input, offset);
		v0.StoreUnsafe(ref output, offset);
		v1 ^= Vector128.LoadUnsafe(ref input, offset + 16);
		v1.StoreUnsafe(ref output, offset + 16);
		v2 ^= Vector128.LoadUnsafe(ref input, offset + 32);
		v2.StoreUnsafe(ref output, offset + 32);
		v3 ^= Vector128.LoadUnsafe(ref input, offset + 48);
		v3.StoreUnsafe(ref output, offset + 48);
		v4 ^= Vector128.LoadUnsafe(ref input, offset + 64);
		v4.StoreUnsafe(ref output, offset + 64);
		v5 ^= Vector128.LoadUnsafe(ref input, offset + 80);
		v5.StoreUnsafe(ref output, offset + 80);
		v6 ^= Vector128.LoadUnsafe(ref input, offset + 96);
		v6.StoreUnsafe(ref output, offset + 96);
		v7 ^= Vector128.LoadUnsafe(ref input, offset + 112);
		v7.StoreUnsafe(ref output, offset + 112);
	}
}
