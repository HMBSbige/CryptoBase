namespace CryptoBase.Kems.MLKem;

// Each operation takes the widest kernel that supports it.
internal readonly struct MLKemKernelDispatch : IMLKemKernel
{
	public static bool IsSupported => true;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Ntt(Span<short> f)
	{
		if (MLKemAvx512.IsSupported)
		{
			MLKemAvx512.Ntt(f);
		}
		else if (MLKemAvx2.IsSupported)
		{
			MLKemAvx2.Ntt(f);
		}
		else if (MLKemVector128.IsSupported)
		{
			MLKemVector128.Ntt(f);
		}
		else
		{
			MLKemScalar.Ntt(f);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void InverseNtt(Span<short> f)
	{
		if (MLKemAvx512.IsSupported)
		{
			MLKemAvx512.InverseNtt(f);
		}
		else if (MLKemAvx2.IsSupported)
		{
			MLKemAvx2.InverseNtt(f);
		}
		else if (MLKemVector128.IsSupported)
		{
			MLKemVector128.InverseNtt(f);
		}
		else
		{
			MLKemScalar.InverseNtt(f);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyAccumulate(ReadOnlySpan<short> a, int aStride, ReadOnlySpan<short> b, Span<short> destination, int count)
	{
		if (MLKemAvx512.IsSupported)
		{
			MLKemAvx512.MultiplyAccumulate(a, aStride, b, destination, count);
		}
		else if (MLKemAvx2.IsSupported)
		{
			MLKemAvx2.MultiplyAccumulate(a, aStride, b, destination, count);
		}
		else if (MLKemVector128.IsSupported)
		{
			MLKemVector128.MultiplyAccumulate(a, aStride, b, destination, count);
		}
		else
		{
			MLKemScalar.MultiplyAccumulate(a, aStride, b, destination, count);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Reduce(Span<short> f)
	{
		if (MLKemAvx512.IsSupported)
		{
			MLKemAvx512.Reduce(f);
		}
		else if (MLKemAvx2.IsSupported)
		{
			MLKemAvx2.Reduce(f);
		}
		else if (MLKemVector128.IsSupported)
		{
			MLKemVector128.Reduce(f);
		}
		else
		{
			MLKemScalar.Reduce(f);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ToMontgomery(Span<short> f)
	{
		if (MLKemAvx512.IsSupported)
		{
			MLKemAvx512.ToMontgomery(f);
		}
		else if (MLKemAvx2.IsSupported)
		{
			MLKemAvx2.ToMontgomery(f);
		}
		else if (MLKemVector128.IsSupported)
		{
			MLKemVector128.ToMontgomery(f);
		}
		else
		{
			MLKemScalar.ToMontgomery(f);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Add(ReadOnlySpan<short> left, ReadOnlySpan<short> right, Span<short> destination)
	{
		if (MLKemAvx512.IsSupported)
		{
			MLKemAvx512.Add(left, right, destination);
		}
		else if (MLKemAvx2.IsSupported)
		{
			MLKemAvx2.Add(left, right, destination);
		}
		else if (MLKemVector128.IsSupported)
		{
			MLKemVector128.Add(left, right, destination);
		}
		else
		{
			MLKemScalar.Add(left, right, destination);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Subtract(ReadOnlySpan<short> left, ReadOnlySpan<short> right, Span<short> destination)
	{
		if (MLKemAvx512.IsSupported)
		{
			MLKemAvx512.Subtract(left, right, destination);
		}
		else if (MLKemAvx2.IsSupported)
		{
			MLKemAvx2.Subtract(left, right, destination);
		}
		else if (MLKemVector128.IsSupported)
		{
			MLKemVector128.Subtract(left, right, destination);
		}
		else
		{
			MLKemScalar.Subtract(left, right, destination);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Encode12(ReadOnlySpan<short> f, Span<byte> destination)
	{
		if (MLKemAvx512.IsSupported)
		{
			MLKemAvx512.Encode12(f, destination);
		}
		else if (MLKemAvx2.IsSupported)
		{
			MLKemAvx2.Encode12(f, destination);
		}
		else if (MLKemVector128.IsSupported)
		{
			MLKemVector128.Encode12(f, destination);
		}
		else
		{
			MLKemScalar.Encode12(f, destination);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static bool Decode12(ReadOnlySpan<byte> source, Span<short> f)
	{
		if (MLKemAvx512.IsSupported)
		{
			return MLKemAvx512.Decode12(source, f);
		}

		if (MLKemAvx2.IsSupported)
		{
			return MLKemAvx2.Decode12(source, f);
		}

		if (MLKemVector128.IsSupported)
		{
			return MLKemVector128.Decode12(source, f);
		}

		return MLKemScalar.Decode12(source, f);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Compress(ReadOnlySpan<short> f, Span<byte> destination, int bits)
	{
		if (MLKemAvx512.IsSupported)
		{
			MLKemAvx512.Compress(f, destination, bits);
		}
		else if (MLKemAvx2.IsSupported)
		{
			MLKemAvx2.Compress(f, destination, bits);
		}
		else if (MLKemVector128.IsSupported)
		{
			MLKemVector128.Compress(f, destination, bits);
		}
		else
		{
			MLKemScalar.Compress(f, destination, bits);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Decompress(ReadOnlySpan<byte> source, Span<short> f, int bits)
	{
		if (MLKemAvx512.IsSupported)
		{
			MLKemAvx512.Decompress(source, f, bits);
		}
		else if (MLKemAvx2.IsSupported)
		{
			MLKemAvx2.Decompress(source, f, bits);
		}
		else if (MLKemVector128.IsSupported)
		{
			MLKemVector128.Decompress(source, f, bits);
		}
		else
		{
			MLKemScalar.Decompress(source, f, bits);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int RejectSample(ReadOnlySpan<byte> source, Span<short> destination)
	{
		if (MLKemAvx512.IsSupported)
		{
			return MLKemAvx512.RejectSample(source, destination);
		}

		if (MLKemAvx2.IsSupported)
		{
			return MLKemAvx2.RejectSample(source, destination);
		}

		if (MLKemVector128.IsSupported)
		{
			return MLKemVector128.RejectSample(source, destination);
		}

		return MLKemScalar.RejectSample(source, destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void SampleCbd(ReadOnlySpan<byte> source, Span<short> f, int eta)
	{
		if (MLKemAvx512.IsSupported)
		{
			MLKemAvx512.SampleCbd(source, f, eta);
		}
		else if (MLKemAvx2.IsSupported)
		{
			MLKemAvx2.SampleCbd(source, f, eta);
		}
		else if (MLKemVector128.IsSupported)
		{
			MLKemVector128.SampleCbd(source, f, eta);
		}
		else
		{
			MLKemScalar.SampleCbd(source, f, eta);
		}
	}
}
