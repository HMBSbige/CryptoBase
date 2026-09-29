namespace CryptoBase.Ciphers.Blocks.SM4;

internal readonly partial struct SM4Gfni
{
	internal const int CtrBatchSize = 64 * 16;

	internal static bool SupportsCtr512
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => IsSupported && MaxBlocks is 64;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void XorCtr128(ref readonly uint rk, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Debug.Assert(SupportsCtr512 && source.Length >= CtrBatchSize && source.Length % CtrBatchSize is 0 && destination.Length >= source.Length);

		SM4CtrPolicy512 policy = new(counter);
		XorCtr(in rk, source, destination, ref policy);
		counter = policy.Counter;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void XorCtr32(ref readonly uint rk, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Debug.Assert(SupportsCtr512 && source.Length >= CtrBatchSize && source.Length % CtrBatchSize is 0 && destination.Length >= source.Length);

		SM4Ctr32Policy512 policy = new(counter);
		XorCtr(in rk, source, destination, ref policy);
		counter = policy.Counter;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void XorCtr<TPolicy>(ref readonly uint rk, ReadOnlySpan<byte> source, Span<byte> destination, ref TPolicy policy) where TPolicy : struct, ISM4ModePolicy512
	{
		for (int offset = 0; offset < source.Length; offset += CtrBatchSize)
		{
			Process64FullV512(in rk, ref Unsafe.Add(ref source.GetReference(), offset), ref Unsafe.Add(ref destination.GetReference(), offset), ref policy);
		}
	}
}
