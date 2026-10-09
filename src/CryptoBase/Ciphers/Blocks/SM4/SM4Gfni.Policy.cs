namespace CryptoBase.Ciphers.Blocks.SM4;

internal readonly partial struct SM4Gfni
{
	private const int PolicyBatchSizeV256 = 16 * 16;
	private const int PolicyBatchSizeV512 = 64 * 16;

	internal static bool SupportsModePolicy
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => IsSupported && MaxBlocks is 16 or 64;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static int TransformBatches<TPolicy>(ref readonly uint rk, ref Vector128<byte> state, ReadOnlySpan<byte> source, Span<byte> destination) where TPolicy : struct, ISM4ModePolicy
	{
		if (!SupportsModePolicy)
		{
			return 0;
		}

		int batchSize = MaxBlocks is 64 ? PolicyBatchSizeV512 : PolicyBatchSizeV256;
		int length = source.Length & -batchSize;

		if (length is 0)
		{
			return 0;
		}

		if (MaxBlocks is 64)
		{
			TransformV512<TPolicy>(in rk, ref state, source.Slice(0, length), destination);
		}
		else
		{
			TransformV256<TPolicy>(in rk, ref state, source.Slice(0, length), destination);
		}

		return length;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void TransformV256<TPolicy>(ref readonly uint rk, ref Vector128<byte> state, ReadOnlySpan<byte> source, Span<byte> destination) where TPolicy : struct, ISM4ModePolicy
	{
		Debug.Assert(source.Length % PolicyBatchSizeV256 is 0 && destination.Length >= source.Length);

		ref byte src = ref MemoryMarshal.GetReference(source);
		ref byte dst = ref MemoryMarshal.GetReference(destination);
		TPolicy policy = default;
		policy.Initialize(state);

		for (int offset = 0; offset < source.Length; offset += PolicyBatchSizeV256)
		{
			Process16V256(in rk, ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset), ref policy);
		}

		policy.SaveState(ref state);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void TransformV512<TPolicy>(ref readonly uint rk, ref Vector128<byte> state, ReadOnlySpan<byte> source, Span<byte> destination) where TPolicy : struct, ISM4ModePolicy
	{
		Debug.Assert(source.Length % PolicyBatchSizeV512 is 0 && destination.Length >= source.Length);

		ref byte src = ref MemoryMarshal.GetReference(source);
		ref byte dst = ref MemoryMarshal.GetReference(destination);
		TPolicy policy = default;
		policy.Initialize(state);

		for (int offset = 0; offset < source.Length; offset += PolicyBatchSizeV512)
		{
			Process64FullV512(in rk, ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset), ref policy);
		}

		policy.SaveState(ref state);
	}
}
