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

		// The 512-bit path finishes every whole block after its 64-block batches with one fused kernel run.
		int length = source.Length & (MaxBlocks is 64 ? -16 : -(16 * 16));

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
		Debug.Assert(source.Length % 16 is 0 && destination.Length >= source.Length);

		ref byte src = ref MemoryMarshal.GetReference(source);
		ref byte dst = ref MemoryMarshal.GetReference(destination);
		TPolicy policy = default;
		policy.Initialize(state);

		// Check the ISAs directly: MaxBlocks folds too late, and the dead path's ref policy argument would block promotion.
		if (Vector512.IsHardwareAccelerated && Gfni.V512.IsSupported)
		{
			int offset = 0;

			for (; source.Length - offset >= 64 * 16; offset += 64 * 16)
			{
				Process64FullV512(in rk, ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset), ref policy);
			}

			if (offset < source.Length)
			{
				ProcessUpTo64V512(source.Length - offset >> 4, in rk, ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset), ref policy);
			}
		}
		else
		{
			for (int offset = 0; offset < source.Length; offset += 16 * 16)
			{
				Process16V256(in rk, ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset), ref policy);
			}
		}

		policy.SaveState(ref state);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ProcessUpTo64V512<TPolicy>(int count, ref readonly uint rk, ref byte source, ref byte destination, ref TPolicy policy) where TPolicy : struct, ISM4ModePolicy
	{
		Debug.Assert(count is > 0 and <= 64);

		switch (count)
		{
			case 16:
			{
				Process16FullV512(in rk, ref source, ref destination, ref policy);
				break;
			}
			case 32:
			{
				Process32FullV512(in rk, ref source, ref destination, ref policy);
				break;
			}
			case 48:
			{
				Process48FullV512(in rk, ref source, ref destination, ref policy);
				break;
			}
			case 64:
			{
				Process64FullV512(in rk, ref source, ref destination, ref policy);
				break;
			}
			default:
			{
				ProcessPartialV512(count, in rk, ref source, ref destination, ref policy);
				break;
			}
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ProcessPartialV512<TPolicy>(int count, ref readonly uint rk, ref byte source, ref byte destination, ref TPolicy policy) where TPolicy : struct, ISM4ModePolicy
	{
		Debug.Assert(count is > 0 and < 64 && count % 16 is not 0);

		// A kernel run costs about the same for one to four 16-block groups, so the tail takes one run with only its last group partial.
		if (count < 16)
		{
			Process16PartialV512(count, in rk, ref source, ref destination, ref policy);
		}
		else if (count < 32)
		{
			Process32PartialV512(count, in rk, ref source, ref destination, ref policy);
		}
		else if (count < 48)
		{
			Process48PartialV512(count, in rk, ref source, ref destination, ref policy);
		}
		else
		{
			Process64PartialV512(count, in rk, ref source, ref destination, ref policy);
		}
	}
}
