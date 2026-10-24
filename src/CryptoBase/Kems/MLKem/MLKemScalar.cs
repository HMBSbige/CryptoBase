namespace CryptoBase.Kems.MLKem;

internal readonly struct MLKemScalar : IMLKemKernel
{
	private const int N = MLKemConstants.N;
	private const short Q = MLKemConstants.Q;

	public static bool IsSupported => true;

	// Each of the seven layers adds less than q to a coefficient, so they stay below 8q < 2^15 until the final reduction.
	public static void Ntt(Span<short> f)
	{
		Debug.Assert(f.Length is N);

		ref short coefficients = ref MemoryMarshal.GetReference(f);
		ref short zetas = ref MemoryMarshal.GetReference(MLKemConstants.Zetas);
		nint k = 1;

		for (nint length = N / 2; length >= 2; length >>= 1)
		{
			for (nint start = 0; start < N; start += 2 * length)
			{
				short zeta = Unsafe.Add(ref zetas, k++);
				ref short low = ref Unsafe.Add(ref coefficients, start);
				ref short high = ref Unsafe.Add(ref low, length);

				for (nint j = 0; j < length; ++j)
				{
					short t = MultiplyMontgomery(zeta, Unsafe.Add(ref high, j));
					short x = Unsafe.Add(ref low, j);
					Unsafe.Add(ref high, j) = (short)(x - t);
					Unsafe.Add(ref low, j) = (short)(x + t);
				}
			}
		}

		Reduce(f);
	}

	// Coefficients stay below q in every layer.
	public static void InverseNtt(Span<short> f)
	{
		Debug.Assert(f.Length is N);

		ref short coefficients = ref MemoryMarshal.GetReference(f);
		ref short zetas = ref MemoryMarshal.GetReference(MLKemConstants.Zetas);
		nint k = 127;

		for (nint length = 2; length <= N / 2; length <<= 1)
		{
			for (nint start = 0; start < N; start += 2 * length)
			{
				short zeta = Unsafe.Add(ref zetas, k--);
				ref short low = ref Unsafe.Add(ref coefficients, start);
				ref short high = ref Unsafe.Add(ref low, length);

				for (nint j = 0; j < length; ++j)
				{
					short x = Unsafe.Add(ref low, j);
					short y = Unsafe.Add(ref high, j);
					Unsafe.Add(ref low, j) = BarrettReduce((short)(x + y));
					Unsafe.Add(ref high, j) = MultiplyMontgomery(zeta, (short)(y - x));
				}
			}
		}

		for (nint i = 0; i < N; ++i)
		{
			Unsafe.Add(ref coefficients, i) = MultiplyMontgomery(Unsafe.Add(ref coefficients, i), MLKemConstants.InverseNttFactor);
		}
	}

	// Each pair is a product modulo X² ∓ γ. A term is below 2q², so the sums of four stay below q · 2^15, the input bound of MontgomeryReduce.
	public static void MultiplyAccumulate(ReadOnlySpan<short> a, int aStride, ReadOnlySpan<short> b, Span<short> destination, int count)
	{
		Debug.Assert(count is >= 1 and <= 4);
		Debug.Assert(aStride >= N && a.Length >= (count - 1) * aStride + N && b.Length >= count * N && destination.Length is N);

		ref short x = ref MemoryMarshal.GetReference(a);
		ref short y = ref MemoryMarshal.GetReference(b);
		ref short z = ref MemoryMarshal.GetReference(destination);
		ref short gammas = ref Unsafe.Add(ref MemoryMarshal.GetReference(MLKemConstants.Zetas), 64);

		for (nint i = 0; i < N; i += 4)
		{
			int gamma = Unsafe.Add(ref gammas, i >> 2);
			int c0 = 0;
			int c1 = 0;
			int c2 = 0;
			int c3 = 0;

			for (nint j = 0; j < count; ++j)
			{
				ref short p = ref Unsafe.Add(ref x, j * aStride + i);
				ref short r = ref Unsafe.Add(ref y, j * N + i);
				int p0 = p;
				int p1 = Unsafe.Add(ref p, 1);
				int p2 = Unsafe.Add(ref p, 2);
				int p3 = Unsafe.Add(ref p, 3);
				int r0 = r;
				int r1 = Unsafe.Add(ref r, 1);
				int r2 = Unsafe.Add(ref r, 2);
				int r3 = Unsafe.Add(ref r, 3);

				c0 += p0 * r0 + MontgomeryReduce(p1 * r1) * gamma;
				c1 += p0 * r1 + p1 * r0;
				c2 += p2 * r2 - MontgomeryReduce(p3 * r3) * gamma;
				c3 += p2 * r3 + p3 * r2;
			}

			Unsafe.Add(ref z, i) = MontgomeryReduce(c0);
			Unsafe.Add(ref z, i + 1) = MontgomeryReduce(c1);
			Unsafe.Add(ref z, i + 2) = MontgomeryReduce(c2);
			Unsafe.Add(ref z, i + 3) = MontgomeryReduce(c3);
		}
	}

	public static void Reduce(Span<short> f)
	{
		for (int i = 0; i < f.Length; ++i)
		{
			f[i] = BarrettReduce(f[i]);
		}
	}

	public static void ToMontgomery(Span<short> f)
	{
		for (int i = 0; i < f.Length; ++i)
		{
			f[i] = MultiplyMontgomery(f[i], MLKemConstants.RSquared);
		}
	}

	public static void Add(ReadOnlySpan<short> left, ReadOnlySpan<short> right, Span<short> destination)
	{
		Debug.Assert(left.Length is N && right.Length is N && destination.Length is N);

		for (int i = 0; i < destination.Length; ++i)
		{
			destination[i] = (short)(left[i] + right[i]);
		}
	}

	public static void Subtract(ReadOnlySpan<short> left, ReadOnlySpan<short> right, Span<short> destination)
	{
		Debug.Assert(left.Length is N && right.Length is N && destination.Length is N);

		for (int i = 0; i < destination.Length; ++i)
		{
			destination[i] = (short)(left[i] - right[i]);
		}
	}

	public static void Encode12(ReadOnlySpan<short> f, Span<byte> destination)
	{
		Debug.Assert(f.Length is N && destination.Length >= 384);

		for (int i = 0; i < N / 2; ++i)
		{
			uint packed = ToCanonical(f[2 * i]) | ToCanonical(f[2 * i + 1]) << 12;
			destination[3 * i] = (byte)packed;
			destination[3 * i + 1] = (byte)(packed >> 8);
			destination[3 * i + 2] = (byte)(packed >> 16);
		}
	}

	public static bool Decode12(ReadOnlySpan<byte> source, Span<short> f)
	{
		Debug.Assert(source.Length >= 384 && f.Length is N);

		// Stays negative while every value is below q, so that the check takes no branch on the values.
		int belowQ = -1;

		for (int i = 0; i < N / 2; ++i)
		{
			int packed = source[3 * i] | source[3 * i + 1] << 8 | source[3 * i + 2] << 16;
			int low = packed & 0xFFF;
			int high = packed >> 12;
			f[2 * i] = (short)low;
			f[2 * i + 1] = (short)high;
			belowQ &= low - Q & high - Q;
		}

		return belowQ < 0;
	}

	// 256 · d bits fill whole 32-bit words, so the bit buffer is empty at the end.
	public static void Compress(ReadOnlySpan<short> f, Span<byte> destination, int bits)
	{
		Debug.Assert(bits is 1 or 4 or 5 or 10 or 11);
		Debug.Assert(f.Length is N && destination.Length >= 32 * bits);

		ulong mask = (1UL << bits) - 1;
		ulong buffer = 0;
		int buffered = 0;
		int offset = 0;

		for (int i = 0; i < N; ++i)
		{
			ulong numerator = (ToCanonical(f[i]) << bits + 1) + (uint)Q;
			buffer |= (numerator * MLKemConstants.CompressMultiplier >> MLKemConstants.CompressShift & mask) << buffered;
			buffered += bits;

			if (buffered >= 32)
			{
				BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(offset), (uint)buffer);
				buffer >>= 32;
				buffered -= 32;
				offset += sizeof(uint);
			}
		}
	}

	// Decompress_d(y) = ⌈q · y / 2^d⌋ = (q · y + 2^(d − 1)) >> d.
	public static void Decompress(ReadOnlySpan<byte> source, Span<short> f, int bits)
	{
		Debug.Assert(bits is 1 or 4 or 5 or 10 or 11);
		Debug.Assert(source.Length >= 32 * bits && f.Length is N);

		uint mask = (1u << bits) - 1;
		uint half = 1u << bits - 1;
		ulong buffer = 0;
		int buffered = 0;
		int offset = 0;

		for (int i = 0; i < N; ++i)
		{
			if (buffered < bits)
			{
				buffer |= (ulong)BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(offset)) << buffered;
				buffered += 32;
				offset += sizeof(uint);
			}

			uint y = (uint)buffer & mask;
			buffer >>= bits;
			buffered -= bits;
			f[i] = (short)(y * (uint)Q + half >> bits);
		}
	}

	public static int RejectSample(ReadOnlySpan<byte> source, Span<short> destination)
	{
		Debug.Assert(source.Length % 3 is 0);

		int count = 0;

		for (int i = 0; i < source.Length && count < destination.Length; i += 3)
		{
			int d1 = source[i] | (source[i + 1] & 0xF) << 8;
			int d2 = source[i + 1] >> 4 | source[i + 2] << 4;

			if (d1 < Q)
			{
				destination[count++] = (short)d1;
			}

			if (d2 < Q && count < destination.Length)
			{
				destination[count++] = (short)d2;
			}
		}

		return count;
	}

	public static void SampleCbd(ReadOnlySpan<byte> source, Span<short> f, int eta)
	{
		Debug.Assert(eta is 2 or 3);
		Debug.Assert(source.Length >= 64 * eta && f.Length is N);

		if (eta is 2)
		{
			SampleCbd2(source, f);
		}
		else
		{
			SampleCbd3(source, f);
		}
	}

	// Coefficient j of each word is bits 4j and 4j + 1 minus bits 4j + 2 and 4j + 3, summed in two-bit fields.
	private static void SampleCbd2(ReadOnlySpan<byte> source, Span<short> f)
	{
		for (int i = 0; i < N / 8; ++i)
		{
			uint bits = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(4 * i));
			uint sums = (bits & 0x55555555) + (bits >> 1 & 0x55555555);

			for (int j = 0; j < 8; ++j)
			{
				int x = (int)(sums >> 4 * j & 3);
				int y = (int)(sums >> 4 * j + 2 & 3);
				f[8 * i + j] = (short)(x - y);
			}
		}
	}

	// The same with three bits each, four coefficients to three bytes.
	private static void SampleCbd3(ReadOnlySpan<byte> source, Span<short> f)
	{
		for (int i = 0; i < N / 4; ++i)
		{
			uint bits = source[3 * i] | (uint)source[3 * i + 1] << 8 | (uint)source[3 * i + 2] << 16;
			uint sums = (bits & 0x249249) + (bits >> 1 & 0x249249) + (bits >> 2 & 0x249249);

			for (int j = 0; j < 4; ++j)
			{
				int x = (int)(sums >> 6 * j & 7);
				int y = (int)(sums >> 6 * j + 3 & 7);
				f[4 * i + j] = (short)(x - y);
			}
		}
	}

	// a · R⁻¹ mod q for |a| < q · 2^15, in (−q, q).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static short MontgomeryReduce(int a)
	{
		short t = (short)(a * MLKemConstants.QInverse);
		return (short)(a - t * Q >> 16);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static short MultiplyMontgomery(short a, short b)
	{
		return MontgomeryReduce(a * b);
	}

	// In [−(q − 1) / 2, (q − 1) / 2].
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static short BarrettReduce(short a)
	{
		int t = MLKemConstants.BarrettMultiplier * a + (1 << 25) >> 26;
		return (short)(a - t * Q);
	}

	// Maps (−q, q) to [0, q).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint ToCanonical(short x)
	{
		return (uint)(x + (x >> 15 & Q));
	}
}
