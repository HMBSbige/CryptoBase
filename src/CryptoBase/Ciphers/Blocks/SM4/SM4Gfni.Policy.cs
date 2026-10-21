namespace CryptoBase.Ciphers.Blocks.SM4;

internal readonly partial struct SM4Gfni
{
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

		int length = source.Length & -(MaxBlocks * 16);

		if (length is 0)
		{
			return 0;
		}

		Transform<TPolicy>(in rk, ref state, source.Slice(0, length), destination);
		return length;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Transform<TPolicy>(ref readonly uint rk, ref Vector128<byte> state, ReadOnlySpan<byte> source, Span<byte> destination) where TPolicy : struct, ISM4ModePolicy
	{
		int batchSize = MaxBlocks * 16;
		Debug.Assert(source.Length % batchSize is 0 && destination.Length >= source.Length);

		ref byte src = ref MemoryMarshal.GetReference(source);
		ref byte dst = ref MemoryMarshal.GetReference(destination);
		TPolicy policy = default;
		policy.Initialize(state);

		for (int offset = 0; offset < source.Length; offset += batchSize)
		{
			// Check the ISAs directly: MaxBlocks folds too late, and the dead path's ref policy argument would block promotion.
			if (Vector512.IsHardwareAccelerated && Gfni.V512.IsSupported)
			{
				Process64FullV512(in rk, ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset), ref policy);
			}
			else
			{
				Process16V256(in rk, ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset), ref policy);
			}
		}

		policy.SaveState(ref state);
	}
}
