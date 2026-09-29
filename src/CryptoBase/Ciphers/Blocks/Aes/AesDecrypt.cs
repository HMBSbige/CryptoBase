namespace CryptoBase.Ciphers.Blocks.Aes;

internal readonly struct AesDecrypt : IAesOperation
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<byte> Apply1<TCore>(ref TCore core, Vector128<byte> value) where TCore : struct, IAesVectorCore
	{
		return core.Decrypt(value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Apply2<TCore>(ref TCore core, ref Vector128<byte> v0, ref Vector128<byte> v1) where TCore : struct, IAesVectorCore
	{
		core.Decrypt2(ref v0, ref v1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Apply4<TCore>(ref TCore core, ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3) where TCore : struct, IAesVectorCore
	{
		core.Decrypt4(ref v0, ref v1, ref v2, ref v3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Apply8<TCore>(ref TCore core, ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7) where TCore : struct, IAesVectorCore
	{
		core.Decrypt8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<byte> Apply1(in AesCipherVpaes core, Vector128<byte> value)
	{
		return core.Decrypt(value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Apply2(in AesCipherVpaes core, ref Vector128<byte> v0, ref Vector128<byte> v1)
	{
		core.Decrypt2(ref v0, ref v1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Apply3(in AesCipherVpaes core, ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2)
	{
		core.Decrypt3(ref v0, ref v1, ref v2);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Apply4(in AesCipherVpaes core, ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3)
	{
		core.Decrypt4(ref v0, ref v1, ref v2, ref v3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ApplyBatch<TPolicy>(in AesCipherBitslice core, ref TPolicy policy, ref byte input, ref byte output, nuint offset, int length, int rounds) where TPolicy : struct, IAesModePolicy, allows ref struct
	{
		core.DecryptBatch(ref policy, ref input, ref output, offset, length, rounds);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ApplyBlocks(in AesCipherSoftware core, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		core.DecryptBlocks(source, destination);
	}
}
