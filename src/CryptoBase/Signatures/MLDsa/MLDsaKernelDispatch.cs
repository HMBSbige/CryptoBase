namespace CryptoBase.Signatures.MLDsa;

// Each operation takes the widest kernel that supports it.
internal readonly struct MLDsaKernelDispatch : IMLDsaKernel
{
	public static bool IsSupported => true;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Ntt(Span<int> f)
	{
		if (MLDsaAvx512.IsSupported)
		{
			MLDsaAvx512.Ntt(f);
		}
		else if (MLDsaAvx2.IsSupported)
		{
			MLDsaAvx2.Ntt(f);
		}
		else if (MLDsaVector128.IsSupported)
		{
			MLDsaVector128.Ntt(f);
		}
		else
		{
			MLDsaScalar.Ntt(f);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void InverseNtt(Span<int> f)
	{
		if (MLDsaAvx512.IsSupported)
		{
			MLDsaAvx512.InverseNtt(f);
		}
		else if (MLDsaAvx2.IsSupported)
		{
			MLDsaAvx2.InverseNtt(f);
		}
		else if (MLDsaVector128.IsSupported)
		{
			MLDsaVector128.InverseNtt(f);
		}
		else
		{
			MLDsaScalar.InverseNtt(f);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyAccumulate(ReadOnlySpan<int> a, ReadOnlySpan<int> b, Span<int> destination, int count)
	{
		if (MLDsaAvx512.IsSupported)
		{
			MLDsaAvx512.MultiplyAccumulate(a, b, destination, count);
		}
		else if (MLDsaAvx2.IsSupported)
		{
			MLDsaAvx2.MultiplyAccumulate(a, b, destination, count);
		}
		else if (MLDsaVector128.IsSupported)
		{
			MLDsaVector128.MultiplyAccumulate(a, b, destination, count);
		}
		else
		{
			MLDsaScalar.MultiplyAccumulate(a, b, destination, count);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Reduce(Span<int> f)
	{
		if (MLDsaAvx512.IsSupported)
		{
			MLDsaAvx512.Reduce(f);
		}
		else if (MLDsaAvx2.IsSupported)
		{
			MLDsaAvx2.Reduce(f);
		}
		else if (MLDsaVector128.IsSupported)
		{
			MLDsaVector128.Reduce(f);
		}
		else
		{
			MLDsaScalar.Reduce(f);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Add(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination)
	{
		if (MLDsaAvx512.IsSupported)
		{
			MLDsaAvx512.Add(left, right, destination);
		}
		else if (MLDsaAvx2.IsSupported)
		{
			MLDsaAvx2.Add(left, right, destination);
		}
		else if (MLDsaVector128.IsSupported)
		{
			MLDsaVector128.Add(left, right, destination);
		}
		else
		{
			MLDsaScalar.Add(left, right, destination);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static bool ExceedsBound(ReadOnlySpan<int> f, int bound)
	{
		if (MLDsaAvx512.IsSupported)
		{
			return MLDsaAvx512.ExceedsBound(f, bound);
		}

		if (MLDsaAvx2.IsSupported)
		{
			return MLDsaAvx2.ExceedsBound(f, bound);
		}

		if (MLDsaVector128.IsSupported)
		{
			return MLDsaVector128.ExceedsBound(f, bound);
		}

		return MLDsaScalar.ExceedsBound(f, bound);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static bool AddReduceExceedsBound(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination, int bound)
	{
		if (MLDsaAvx512.IsSupported)
		{
			return MLDsaAvx512.AddReduceExceedsBound(left, right, destination, bound);
		}

		if (MLDsaAvx2.IsSupported)
		{
			return MLDsaAvx2.AddReduceExceedsBound(left, right, destination, bound);
		}

		if (MLDsaVector128.IsSupported)
		{
			return MLDsaVector128.AddReduceExceedsBound(left, right, destination, bound);
		}

		return MLDsaScalar.AddReduceExceedsBound(left, right, destination, bound);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static bool SubtractReduceExceedsBound(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination, int bound)
	{
		if (MLDsaAvx512.IsSupported)
		{
			return MLDsaAvx512.SubtractReduceExceedsBound(left, right, destination, bound);
		}

		if (MLDsaAvx2.IsSupported)
		{
			return MLDsaAvx2.SubtractReduceExceedsBound(left, right, destination, bound);
		}

		if (MLDsaVector128.IsSupported)
		{
			return MLDsaVector128.SubtractReduceExceedsBound(left, right, destination, bound);
		}

		return MLDsaScalar.SubtractReduceExceedsBound(left, right, destination, bound);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static bool ReduceExceedsBound(Span<int> f, int bound)
	{
		if (MLDsaAvx512.IsSupported)
		{
			return MLDsaAvx512.ReduceExceedsBound(f, bound);
		}

		if (MLDsaAvx2.IsSupported)
		{
			return MLDsaAvx2.ReduceExceedsBound(f, bound);
		}

		if (MLDsaVector128.IsSupported)
		{
			return MLDsaVector128.ReduceExceedsBound(f, bound);
		}

		return MLDsaScalar.ReduceExceedsBound(f, bound);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Power2Round(ReadOnlySpan<int> t, Span<int> high, Span<int> low)
	{
		if (MLDsaAvx512.IsSupported)
		{
			MLDsaAvx512.Power2Round(t, high, low);
		}
		else if (MLDsaAvx2.IsSupported)
		{
			MLDsaAvx2.Power2Round(t, high, low);
		}
		else if (MLDsaVector128.IsSupported)
		{
			MLDsaVector128.Power2Round(t, high, low);
		}
		else
		{
			MLDsaScalar.Power2Round(t, high, low);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Decompose(ReadOnlySpan<int> r, Span<int> high, Span<int> low, int gamma2)
	{
		if (MLDsaAvx512.IsSupported)
		{
			MLDsaAvx512.Decompose(r, high, low, gamma2);
		}
		else if (MLDsaAvx2.IsSupported)
		{
			MLDsaAvx2.Decompose(r, high, low, gamma2);
		}
		else if (MLDsaVector128.IsSupported)
		{
			MLDsaVector128.Decompose(r, high, low, gamma2);
		}
		else
		{
			MLDsaScalar.Decompose(r, high, low, gamma2);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int MakeHint(ReadOnlySpan<int> low, ReadOnlySpan<int> high, Span<int> hint, int gamma2)
	{
		if (MLDsaAvx512.IsSupported)
		{
			return MLDsaAvx512.MakeHint(low, high, hint, gamma2);
		}

		if (MLDsaAvx2.IsSupported)
		{
			return MLDsaAvx2.MakeHint(low, high, hint, gamma2);
		}

		if (MLDsaVector128.IsSupported)
		{
			return MLDsaVector128.MakeHint(low, high, hint, gamma2);
		}

		return MLDsaScalar.MakeHint(low, high, hint, gamma2);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void UseHint(ReadOnlySpan<int> r, ReadOnlySpan<int> hint, Span<int> destination, int gamma2)
	{
		if (MLDsaAvx512.IsSupported)
		{
			MLDsaAvx512.UseHint(r, hint, destination, gamma2);
		}
		else if (MLDsaAvx2.IsSupported)
		{
			MLDsaAvx2.UseHint(r, hint, destination, gamma2);
		}
		else if (MLDsaVector128.IsSupported)
		{
			MLDsaVector128.UseHint(r, hint, destination, gamma2);
		}
		else
		{
			MLDsaScalar.UseHint(r, hint, destination, gamma2);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int RejectSample(ReadOnlySpan<byte> source, Span<int> destination)
	{
		if (MLDsaAvx512.IsSupported)
		{
			return MLDsaAvx512.RejectSample(source, destination);
		}

		if (MLDsaAvx2.IsSupported)
		{
			return MLDsaAvx2.RejectSample(source, destination);
		}

		if (MLDsaVector128.IsSupported)
		{
			return MLDsaVector128.RejectSample(source, destination);
		}

		return MLDsaScalar.RejectSample(source, destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int RejectEta(ReadOnlySpan<byte> source, Span<int> destination, int eta)
	{
		if (MLDsaAvx512.IsSupported)
		{
			return MLDsaAvx512.RejectEta(source, destination, eta);
		}

		if (MLDsaAvx2.IsSupported)
		{
			return MLDsaAvx2.RejectEta(source, destination, eta);
		}

		if (MLDsaVector128.IsSupported)
		{
			return MLDsaVector128.RejectEta(source, destination, eta);
		}

		return MLDsaScalar.RejectEta(source, destination, eta);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void EncodeT1(ReadOnlySpan<int> t1, Span<byte> destination)
	{
		if (MLDsaAvx512.IsSupported)
		{
			MLDsaAvx512.EncodeT1(t1, destination);
		}
		else if (MLDsaAvx2.IsSupported)
		{
			MLDsaAvx2.EncodeT1(t1, destination);
		}
		else if (MLDsaVector128.IsSupported)
		{
			MLDsaVector128.EncodeT1(t1, destination);
		}
		else
		{
			MLDsaScalar.EncodeT1(t1, destination);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void DecodeT1(ReadOnlySpan<byte> source, Span<int> f)
	{
		if (MLDsaAvx512.IsSupported)
		{
			MLDsaAvx512.DecodeT1(source, f);
		}
		else if (MLDsaAvx2.IsSupported)
		{
			MLDsaAvx2.DecodeT1(source, f);
		}
		else if (MLDsaVector128.IsSupported)
		{
			MLDsaVector128.DecodeT1(source, f);
		}
		else
		{
			MLDsaScalar.DecodeT1(source, f);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void EncodeT0(ReadOnlySpan<int> t0, Span<byte> destination)
	{
		if (MLDsaAvx512.IsSupported)
		{
			MLDsaAvx512.EncodeT0(t0, destination);
		}
		else if (MLDsaAvx2.IsSupported)
		{
			MLDsaAvx2.EncodeT0(t0, destination);
		}
		else if (MLDsaVector128.IsSupported)
		{
			MLDsaVector128.EncodeT0(t0, destination);
		}
		else
		{
			MLDsaScalar.EncodeT0(t0, destination);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void EncodeEta(ReadOnlySpan<int> s, Span<byte> destination, int eta)
	{
		if (MLDsaAvx512.IsSupported)
		{
			MLDsaAvx512.EncodeEta(s, destination, eta);
		}
		else if (MLDsaAvx2.IsSupported)
		{
			MLDsaAvx2.EncodeEta(s, destination, eta);
		}
		else if (MLDsaVector128.IsSupported)
		{
			MLDsaVector128.EncodeEta(s, destination, eta);
		}
		else
		{
			MLDsaScalar.EncodeEta(s, destination, eta);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static bool DecodeEta(ReadOnlySpan<byte> source, Span<int> s, int eta)
	{
		if (MLDsaAvx512.IsSupported)
		{
			return MLDsaAvx512.DecodeEta(source, s, eta);
		}

		if (MLDsaAvx2.IsSupported)
		{
			return MLDsaAvx2.DecodeEta(source, s, eta);
		}

		if (MLDsaVector128.IsSupported)
		{
			return MLDsaVector128.DecodeEta(source, s, eta);
		}

		return MLDsaScalar.DecodeEta(source, s, eta);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void EncodeZ(ReadOnlySpan<int> z, Span<byte> destination, int gamma1Bits)
	{
		if (MLDsaAvx512.IsSupported)
		{
			MLDsaAvx512.EncodeZ(z, destination, gamma1Bits);
		}
		else if (MLDsaAvx2.IsSupported)
		{
			MLDsaAvx2.EncodeZ(z, destination, gamma1Bits);
		}
		else if (MLDsaVector128.IsSupported)
		{
			MLDsaVector128.EncodeZ(z, destination, gamma1Bits);
		}
		else
		{
			MLDsaScalar.EncodeZ(z, destination, gamma1Bits);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void DecodeZ(ReadOnlySpan<byte> source, Span<int> z, int gamma1Bits)
	{
		if (MLDsaAvx512.IsSupported)
		{
			MLDsaAvx512.DecodeZ(source, z, gamma1Bits);
		}
		else if (MLDsaAvx2.IsSupported)
		{
			MLDsaAvx2.DecodeZ(source, z, gamma1Bits);
		}
		else if (MLDsaVector128.IsSupported)
		{
			MLDsaVector128.DecodeZ(source, z, gamma1Bits);
		}
		else
		{
			MLDsaScalar.DecodeZ(source, z, gamma1Bits);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void EncodeW1(ReadOnlySpan<int> w1, Span<byte> destination, int gamma2)
	{
		if (MLDsaAvx512.IsSupported)
		{
			MLDsaAvx512.EncodeW1(w1, destination, gamma2);
		}
		else if (MLDsaAvx2.IsSupported)
		{
			MLDsaAvx2.EncodeW1(w1, destination, gamma2);
		}
		else if (MLDsaVector128.IsSupported)
		{
			MLDsaVector128.EncodeW1(w1, destination, gamma2);
		}
		else
		{
			MLDsaScalar.EncodeW1(w1, destination, gamma2);
		}
	}
}
