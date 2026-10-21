using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Kems.MLKem;

// Sixteen coefficients per 256-bit vector. Encoders and decoders never access past the end of a buffer. The operations that loop or
// hold many vectors are not inlined, as merged into a large caller their vectors end up on the stack.
internal readonly partial struct MLKemAvx2 : IMLKemKernel
{
	private const int N = MLKemConstants.N;
	private const short Q = MLKemConstants.Q;

	public static bool IsSupported => Avx2.IsSupported;

	// Each half stays in eight registers after layer 1. A product by a zeta is below 3q/4, so seven layers keep the coefficients below
	// q + 7 · 3q/4 < 2^15 without reduction.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void Ntt(Span<short> f)
	{
		Debug.Assert(f.Length is N);

		ref Vector256<short> coefficients = ref Unsafe.As<short, Vector256<short>>(ref MemoryMarshal.GetReference(f));
		ref Vector256<short> zetas = ref Unsafe.As<short, Vector256<short>>(ref MemoryMarshal.GetReference(NttZetas));

		for (nint i = 0; i < 8; ++i)
		{
			Butterfly(ref Unsafe.Add(ref coefficients, i), ref Unsafe.Add(ref coefficients, i + 8), ref zetas);
		}

		for (nint half = 0; half < 2; ++half)
		{
			NttHalf(ref Unsafe.Add(ref coefficients, 8 * half), ref Unsafe.Add(ref zetas, 2 + 38 * half));
		}
	}

	// The mirror of Ntt. Sums double their bound, so reducing those of layers 3 and 6 keeps every difference within 16 bits.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void InverseNtt(Span<short> f)
	{
		Debug.Assert(f.Length is N);

		ref Vector256<short> coefficients = ref Unsafe.As<short, Vector256<short>>(ref MemoryMarshal.GetReference(f));
		ref Vector256<short> zetas = ref Unsafe.As<short, Vector256<short>>(ref MemoryMarshal.GetReference(InverseNttZetas));

		for (nint half = 0; half < 2; ++half)
		{
			InverseNttHalf(ref Unsafe.Add(ref coefficients, 8 * half), ref Unsafe.Add(ref zetas, 38 * half));
		}

		for (nint i = 0; i < 8; ++i)
		{
			ref Vector256<short> low = ref Unsafe.Add(ref coefficients, i);
			ref Vector256<short> high = ref Unsafe.Add(ref low, 8);
			Vector256<short> sum = low + high;
			Vector256<short> difference = high - low;
			low = MultiplyMontgomery(sum, Vector256.Create(MLKemConstants.InverseNttFactor), Vector256.Create(MLKemConstants.InverseNttFactorQInverse));
			high = MultiplyMontgomery(difference, Vector256.Create(MLKemConstants.LastInverseZeta), Vector256.Create(MLKemConstants.LastInverseZetaQInverse));
		}
	}

	// The product modulo X² ∓ γ is (x0·y0 + x1·y1) + (±γ − 1) · x1·y1 + (x0·y1 + x1·y0)·X, each sum one multiply-add. Four terms sum
	// unreduced below 8q² < q · 2^15.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void MultiplyAccumulate(ReadOnlySpan<short> a, int aStride, ReadOnlySpan<short> b, Span<short> destination, int count)
	{
		Debug.Assert(count is >= 1 and <= 4);
		Debug.Assert(aStride >= N && a.Length >= (count - 1) * aStride + N && b.Length >= count * N && destination.Length is N);

		ref short x = ref MemoryMarshal.GetReference(a);
		ref short y = ref MemoryMarshal.GetReference(b);
		ref short z = ref MemoryMarshal.GetReference(destination);
		ref short deltas = ref MemoryMarshal.GetReference(MultiplyDeltas);
		Vector256<int> oddMask = Vector256.Create(unchecked((int)0xFFFF0000));
		Vector256<byte> swap = Vector256.Create(Vector128.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13));

		for (nint i = 0; i < N; i += 16)
		{
			Vector256<int> sums = Vector256<int>.Zero;
			Vector256<int> oddProducts = Vector256<int>.Zero;
			Vector256<int> crossSums = Vector256<int>.Zero;
			ref short left = ref Unsafe.Add(ref x, i);
			ref short right = ref Unsafe.Add(ref y, i);

			for (int j = 0; j < count; ++j)
			{
				Vector256<short> u = Vector256.LoadUnsafe(ref left);
				Vector256<short> v = Vector256.LoadUnsafe(ref right);
				sums += Avx2.MultiplyAddAdjacent(u, v);
				oddProducts += Avx2.MultiplyAddAdjacent(u, (v.AsInt32() & oddMask).AsInt16());
				crossSums += Avx2.MultiplyAddAdjacent(u, Avx2.Shuffle(v.AsByte(), swap).AsInt16());
				left = ref Unsafe.Add(ref left, aStride);
				right = ref Unsafe.Add(ref right, N);
			}

			Vector256<int> evenSums = sums + Avx2.MultiplyAddAdjacent(MontgomeryReduce(oddProducts).AsInt16(), Vector256.LoadUnsafe(ref deltas, (nuint)i));
			(MontgomeryReduce(evenSums) >>> 16 | MontgomeryReduce(crossSums)).AsInt16().StoreUnsafe(ref z, (nuint)i);
		}
	}

	public static void Reduce(Span<short> f)
	{
		Debug.Assert(f.Length is N);

		ref short coefficients = ref MemoryMarshal.GetReference(f);

		for (nuint i = 0; i < N; i += 16)
		{
			Reduce(Vector256.LoadUnsafe(ref coefficients, i)).StoreUnsafe(ref coefficients, i);
		}
	}

	public static void ToMontgomery(Span<short> f)
	{
		Debug.Assert(f.Length is N);

		ref short coefficients = ref MemoryMarshal.GetReference(f);

		for (nuint i = 0; i < N; i += 16)
		{
			Vector256<short> value = Vector256.LoadUnsafe(ref coefficients, i);
			MultiplyMontgomery(value, Vector256.Create(MLKemConstants.RSquared), Vector256.Create(MLKemConstants.RSquaredQInverse)).StoreUnsafe(ref coefficients, i);
		}
	}

	public static void Add(ReadOnlySpan<short> left, ReadOnlySpan<short> right, Span<short> destination)
	{
		Debug.Assert(left.Length is N && right.Length is N && destination.Length is N);

		ref short x = ref MemoryMarshal.GetReference(left);
		ref short y = ref MemoryMarshal.GetReference(right);
		ref short z = ref MemoryMarshal.GetReference(destination);

		for (nuint i = 0; i < N; i += 16)
		{
			(Vector256.LoadUnsafe(ref x, i) + Vector256.LoadUnsafe(ref y, i)).StoreUnsafe(ref z, i);
		}
	}

	public static void Subtract(ReadOnlySpan<short> left, ReadOnlySpan<short> right, Span<short> destination)
	{
		Debug.Assert(left.Length is N && right.Length is N && destination.Length is N);

		ref short x = ref MemoryMarshal.GetReference(left);
		ref short y = ref MemoryMarshal.GetReference(right);
		ref short z = ref MemoryMarshal.GetReference(destination);

		for (nuint i = 0; i < N; i += 16)
		{
			(Vector256.LoadUnsafe(ref x, i) - Vector256.LoadUnsafe(ref y, i)).StoreUnsafe(ref z, i);
		}
	}

	// Sixteen coefficients make 24 bytes, written with 32-byte stores that the next one overwrites, but for the last.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void Encode12(ReadOnlySpan<short> f, Span<byte> destination)
	{
		Debug.Assert(f.Length is N && destination.Length >= 384);

		ref short source = ref MemoryMarshal.GetReference(f);
		ref byte target = ref MemoryMarshal.GetReference(destination);

		for (nint i = 0; i < 15; ++i)
		{
			Encode12(Vector256.LoadUnsafe(ref source, (nuint)(16 * i))).StoreUnsafe(ref target, (nuint)(24 * i));
		}

		Vector256<byte> last = Encode12(Vector256.LoadUnsafe(ref source, 240));
		last.GetLower().StoreUnsafe(ref target, 360);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref target, 376), last.GetUpper().AsUInt64().ToScalar());
	}

	// Each 128-bit lane reads the 16 bytes that end where its 12 do. Only the largest value decides the check, so the time does not
	// depend on where an invalid value lies.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static bool Decode12(ReadOnlySpan<byte> source, Span<short> f)
	{
		Debug.Assert(source.Length >= 384 && f.Length is N);

		ref byte input = ref MemoryMarshal.GetReference(source);
		ref short output = ref MemoryMarshal.GetReference(f);
		Vector256<byte> fields = Vector256.Create((byte)0, 1, 1, 2, 3, 4, 4, 5, 6, 7, 7, 8, 9, 10, 10, 11, 4, 5, 5, 6, 7, 8, 8, 9, 10, 11, 11, 12, 13, 14, 14, 15);
		Vector256<ushort> largest = Vector256<ushort>.Zero;

		for (nint i = 0; i < 16; ++i)
		{
			Vector256<byte> window = Vector256.Create(Vector128.LoadUnsafe(ref input, (nuint)(24 * i)), Vector128.LoadUnsafe(ref input, (nuint)(24 * i + 8)));
			Vector256<ushort> values = Avx2.Shuffle(window, fields).AsUInt16() * Vector256.Create(16 | 1 << 16).AsUInt16() >>> 4;
			largest = Vector256.Max(largest, values);
			values.AsInt16().StoreUnsafe(ref output, (nuint)(16 * i));
		}

		return Vector256.LessThanAll(largest, Vector256.Create((ushort)Q));
	}

	public static void Compress(ReadOnlySpan<short> f, Span<byte> destination, int bits)
	{
		Debug.Assert(bits is 1 or 4 or 5 or 10 or 11);
		Debug.Assert(f.Length is N && destination.Length >= 32 * bits);

		ref short source = ref MemoryMarshal.GetReference(f);
		ref byte target = ref MemoryMarshal.GetReference(destination);

		switch (bits)
		{
			case 1:
			{
				Compress1(ref source, ref target);
				break;
			}
			case 4:
			{
				Compress4(ref source, ref target);
				break;
			}
			case 5:
			{
				Compress5(ref source, ref target);
				break;
			}
			case 10:
			{
				Compress10(ref source, ref target);
				break;
			}
			case 11:
			{
				Compress11(ref source, ref target);
				break;
			}
		}
	}

	public static void Decompress(ReadOnlySpan<byte> source, Span<short> f, int bits)
	{
		Debug.Assert(bits is 1 or 4 or 5 or 10 or 11);
		Debug.Assert(source.Length >= 32 * bits && f.Length is N);

		ref byte input = ref MemoryMarshal.GetReference(source);
		ref short output = ref MemoryMarshal.GetReference(f);

		switch (bits)
		{
			case 1:
			{
				Decompress1(ref input, ref output);
				break;
			}
			case 4:
			{
				Decompress4(ref input, ref output);
				break;
			}
			case 5:
			{
				Decompress5(ref input, ref output);
				break;
			}
			case 10:
			{
				Decompress10(ref input, ref output);
				break;
			}
			case 11:
			{
				Decompress11(ref input, ref output);
				break;
			}
		}
	}

	// The store writes eight lanes however few are accepted, so the values collect in a buffer first. The candidates are public, which
	// allows the lookups and branches.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static int RejectSample(ReadOnlySpan<byte> source, Span<short> destination)
	{
		Debug.Assert(source.Length % 3 is 0);

		const int GroupLength = 24;
		const int BufferLength = N + 16;
		Span<short> buffer = stackalloc short[BufferLength];
		ref byte input = ref MemoryMarshal.GetReference(source);
		ref short output = ref MemoryMarshal.GetReference(buffer);
		ref byte shuffles = ref MemoryMarshal.GetReference(MLKemVector128.RejectShuffles);
		Vector256<byte> fields = Vector256.Create((byte)0, 1, 1, 2, 3, 4, 4, 5, 6, 7, 7, 8, 9, 10, 10, 11, 4, 5, 5, 6, 7, 8, 8, 9, 10, 11, 11, 12, 13, 14, 14, 15);
		int limit = Math.Min(destination.Length, N);
		int count = 0;
		int offset = 0;

		for (; offset <= source.Length - GroupLength && count < limit; offset += GroupLength)
		{
			Vector256<byte> window = Vector256.Create(Vector128.LoadUnsafe(ref input, (nuint)offset), Vector128.LoadUnsafe(ref input, (nuint)offset + 8));
			Vector256<short> candidates = (Avx2.Shuffle(window, fields).AsUInt16() * Vector256.Create(16 | 1 << 16).AsUInt16() >>> 4).AsInt16();
			Vector256<short> accepted = Vector256.LessThan(candidates, Vector256.Create(Q));
			uint mask = Vector256.ExtractMostSignificantBits(Avx2.PackSignedSaturate(accepted, accepted));
			uint low = mask & 0xFF;
			uint high = mask >> 16 & 0xFF;

			Vector128<byte> lowShuffle = Vector128.LoadUnsafe(ref shuffles, 16 * low);
			Ssse3.Shuffle(candidates.GetLower().AsByte(), lowShuffle).StoreUnsafe(ref Unsafe.As<short, byte>(ref Unsafe.Add(ref output, count)));
			count += BitOperations.PopCount(low);
			Vector128<byte> highShuffle = Vector128.LoadUnsafe(ref shuffles, 16 * high);
			Ssse3.Shuffle(candidates.GetUpper().AsByte(), highShuffle).StoreUnsafe(ref Unsafe.As<short, byte>(ref Unsafe.Add(ref output, count)));
			count += BitOperations.PopCount(high);
		}

		count = Math.Min(count, destination.Length);
		buffer.Slice(0, count).CopyTo(destination);

		if (count < destination.Length)
		{
			count += MLKemScalar.RejectSample(source.Slice(offset), destination.Slice(count));
		}

		return count;
	}

	public static void SampleCbd(ReadOnlySpan<byte> source, Span<short> f, int eta)
	{
		Debug.Assert(eta is 2 or 3);
		Debug.Assert(source.Length >= 64 * eta && f.Length is N);

		ref byte input = ref MemoryMarshal.GetReference(source);
		ref short output = ref MemoryMarshal.GetReference(f);

		if (eta is 2)
		{
			SampleCbd2(ref input, ref output);
		}
		else
		{
			SampleCbd3(ref input, ref output);
		}
	}

	// Layers 2 to 7 of NTT on eight vectors from half.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void NttHalf(ref Vector256<short> half, ref Vector256<short> zetas)
	{
		Vector256<short> w0 = half;
		Vector256<short> w1 = Unsafe.Add(ref half, 1);
		Vector256<short> w2 = Unsafe.Add(ref half, 2);
		Vector256<short> w3 = Unsafe.Add(ref half, 3);
		Vector256<short> w4 = Unsafe.Add(ref half, 4);
		Vector256<short> w5 = Unsafe.Add(ref half, 5);
		Vector256<short> w6 = Unsafe.Add(ref half, 6);
		Vector256<short> w7 = Unsafe.Add(ref half, 7);

		Butterfly(ref w0, ref w4, ref zetas);
		Butterfly(ref w1, ref w5, ref zetas);
		Butterfly(ref w2, ref w6, ref zetas);
		Butterfly(ref w3, ref w7, ref zetas);

		Butterfly(ref w0, ref w2, ref Unsafe.Add(ref zetas, 2));
		Butterfly(ref w1, ref w3, ref Unsafe.Add(ref zetas, 2));
		Butterfly(ref w4, ref w6, ref Unsafe.Add(ref zetas, 4));
		Butterfly(ref w5, ref w7, ref Unsafe.Add(ref zetas, 4));

		Butterfly(ref w0, ref w1, ref Unsafe.Add(ref zetas, 6));
		Butterfly(ref w2, ref w3, ref Unsafe.Add(ref zetas, 8));
		Butterfly(ref w4, ref w5, ref Unsafe.Add(ref zetas, 10));
		Butterfly(ref w6, ref w7, ref Unsafe.Add(ref zetas, 12));

		NttPair(w0, w1, ref Unsafe.Add(ref zetas, 14), out half);
		NttPair(w2, w3, ref Unsafe.Add(ref zetas, 20), out Unsafe.Add(ref half, 2));
		NttPair(w4, w5, ref Unsafe.Add(ref zetas, 26), out Unsafe.Add(ref half, 4));
		NttPair(w6, w7, ref Unsafe.Add(ref zetas, 32), out Unsafe.Add(ref half, 6));
	}

	// Layers 5 to 7 of NTT on the 32 coefficients of a and b, written back in order to destination.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void NttPair(Vector256<short> a, Vector256<short> b, ref Vector256<short> zetas, out Vector256<short> destination)
	{
		Vector256<short> low = Avx2.Permute2x128(a, b, 0x20);
		Vector256<short> high = Avx2.Permute2x128(a, b, 0x31);
		Butterfly(ref low, ref high, ref zetas);

		a = Avx2.UnpackLow(low.AsInt64(), high.AsInt64()).AsInt16();
		b = Avx2.UnpackHigh(low.AsInt64(), high.AsInt64()).AsInt16();
		Butterfly(ref a, ref b, ref Unsafe.Add(ref zetas, 2));

		low = Avx2.Blend(a.AsInt32(), (b.AsInt64() << 32).AsInt32(), 0b1010_1010).AsInt16();
		high = Avx2.Blend((a.AsInt64() >>> 32).AsInt32(), b.AsInt32(), 0b1010_1010).AsInt16();
		Butterfly(ref low, ref high, ref Unsafe.Add(ref zetas, 4));
		low = Reduce(low);
		high = Reduce(high);

		a = Avx2.UnpackLow(low.AsInt32(), high.AsInt32()).AsInt16();
		b = Avx2.UnpackHigh(low.AsInt32(), high.AsInt32()).AsInt16();
		destination = Avx2.Permute2x128(a, b, 0x20);
		Unsafe.Add(ref destination, 1) = Avx2.Permute2x128(a, b, 0x31);
	}

	// Layers 1 to 6 of NTT⁻¹ on eight vectors from half.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseNttHalf(ref Vector256<short> half, ref Vector256<short> zetas)
	{
		InverseNttPair(ref half, ref zetas, out Vector256<short> w0, out Vector256<short> w1);
		InverseNttPair(ref Unsafe.Add(ref half, 2), ref Unsafe.Add(ref zetas, 6), out Vector256<short> w2, out Vector256<short> w3);
		InverseNttPair(ref Unsafe.Add(ref half, 4), ref Unsafe.Add(ref zetas, 12), out Vector256<short> w4, out Vector256<short> w5);
		InverseNttPair(ref Unsafe.Add(ref half, 6), ref Unsafe.Add(ref zetas, 18), out Vector256<short> w6, out Vector256<short> w7);

		InverseButterfly(ref w0, ref w1, ref Unsafe.Add(ref zetas, 24));
		InverseButterfly(ref w2, ref w3, ref Unsafe.Add(ref zetas, 26));
		InverseButterfly(ref w4, ref w5, ref Unsafe.Add(ref zetas, 28));
		InverseButterfly(ref w6, ref w7, ref Unsafe.Add(ref zetas, 30));

		InverseButterfly(ref w0, ref w2, ref Unsafe.Add(ref zetas, 32));
		InverseButterfly(ref w1, ref w3, ref Unsafe.Add(ref zetas, 32));
		InverseButterfly(ref w4, ref w6, ref Unsafe.Add(ref zetas, 34));
		InverseButterfly(ref w5, ref w7, ref Unsafe.Add(ref zetas, 34));

		InverseButterfly(ref w0, ref w4, ref Unsafe.Add(ref zetas, 36));
		InverseButterfly(ref w1, ref w5, ref Unsafe.Add(ref zetas, 36));
		InverseButterfly(ref w2, ref w6, ref Unsafe.Add(ref zetas, 36));
		InverseButterfly(ref w3, ref w7, ref Unsafe.Add(ref zetas, 36));

		half = Reduce(w0);
		Unsafe.Add(ref half, 1) = Reduce(w1);
		Unsafe.Add(ref half, 2) = Reduce(w2);
		Unsafe.Add(ref half, 3) = Reduce(w3);
		Unsafe.Add(ref half, 4) = w4;
		Unsafe.Add(ref half, 5) = w5;
		Unsafe.Add(ref half, 6) = w6;
		Unsafe.Add(ref half, 7) = w7;
	}

	// Layers 1 to 3 of NTT⁻¹ on the 32 coefficients at source, undoing the moves of NttPair.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseNttPair(ref Vector256<short> source, ref Vector256<short> zetas, out Vector256<short> first, out Vector256<short> second)
	{
		Vector256<short> a = source;
		Vector256<short> b = Unsafe.Add(ref source, 1);
		Vector256<int> x = Avx2.Shuffle(Avx2.Permute2x128(a, b, 0x20).AsInt32(), 0b11_01_10_00);
		Vector256<int> y = Avx2.Shuffle(Avx2.Permute2x128(a, b, 0x31).AsInt32(), 0b11_01_10_00);
		Vector256<short> low = Avx2.UnpackLow(x.AsInt64(), y.AsInt64()).AsInt16();
		Vector256<short> high = Avx2.UnpackHigh(x.AsInt64(), y.AsInt64()).AsInt16();
		InverseButterfly(ref low, ref high, ref zetas);

		a = Avx2.Blend(low.AsInt32(), (high.AsInt64() << 32).AsInt32(), 0b1010_1010).AsInt16();
		b = Avx2.Blend((low.AsInt64() >>> 32).AsInt32(), high.AsInt32(), 0b1010_1010).AsInt16();
		InverseButterfly(ref a, ref b, ref Unsafe.Add(ref zetas, 2));

		low = Avx2.UnpackLow(a.AsInt64(), b.AsInt64()).AsInt16();
		high = Avx2.UnpackHigh(a.AsInt64(), b.AsInt64()).AsInt16();
		InverseButterfly(ref low, ref high, ref Unsafe.Add(ref zetas, 4));
		low = Reduce(low);

		first = Avx2.Permute2x128(low, high, 0x20);
		second = Avx2.Permute2x128(low, high, 0x31);
	}

	// (x, y) ← (x + ζy, x − ζy) with the zeta pair at zeta.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Butterfly(ref Vector256<short> x, ref Vector256<short> y, ref Vector256<short> zeta)
	{
		Vector256<short> t = MultiplyMontgomery(y, zeta, Unsafe.Add(ref zeta, 1));
		y = x - t;
		x += t;
	}

	// (x, y) ← (x + y, ζ(y − x)) with the zeta pair at zeta.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseButterfly(ref Vector256<short> x, ref Vector256<short> y, ref Vector256<short> zeta)
	{
		Vector256<short> difference = y - x;
		x += y;
		y = MultiplyMontgomery(difference, zeta, Unsafe.Add(ref zeta, 1));
	}

	// a · b · R⁻¹ mod q given bQInverse = b · q⁻¹ mod 2^16, within q/2 + |a · b| / 2^16 of zero.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<short> MultiplyMontgomery(Vector256<short> a, Vector256<short> b, Vector256<short> bQInverse)
	{
		Vector256<short> high = Avx2.MultiplyHigh(a, b);
		Vector256<short> t = a * bQInverse;
		return high - Avx2.MultiplyHigh(t, Vector256.Create(Q));
	}

	// a · R⁻¹ mod q in the upper half of each 32-bit lane and zero in the lower, for |a| < q · 2^15.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<int> MontgomeryReduce(Vector256<int> a)
	{
		Vector256<short> t = a.AsInt16() * Vector256.Create(MLKemConstants.QInverse);
		return a - Avx2.MultiplyAddAdjacent(t, Vector256.Create((int)Q).AsInt16());
	}

	// a − ⌈10a / 2^15⌋ · q, below 2q/3 in magnitude for every 16-bit a.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<short> Reduce(Vector256<short> a)
	{
		Vector256<short> quotient = Avx2.MultiplyHighRoundScale(a, Vector256.Create((short)10));
		return a - quotient * Vector256.Create(Q);
	}

	// The 24 bytes of ByteEncode_12 of sixteen coefficients in (−q, q), then eight zeros.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> Encode12(Vector256<short> x)
	{
		x += x >> 15 & Vector256.Create(Q);
		Vector256<int> pairs = Avx2.MultiplyAddAdjacent(x, Vector256.Create(1 | 4096 << 16).AsInt16());
		Vector256<byte> packed = Avx2.Shuffle(pairs.AsByte(), Vector256.Create(Vector128.Create(0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 0x80, 0x80, 0x80, 0x80)));
		return Avx2.PermuteVar8x32(packed.AsInt32(), Vector256.Create(0, 1, 2, 4, 5, 6, 3, 7)).AsByte();
	}

	// Compress_d for x in (−q, q). The rounded product is off by at most one, which the remainder 2^d · x − y · q, exact modulo 2^16,
	// corrects when beyond q/2.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<short> CompressValues(Vector256<short> x, short multiplier, [ConstantExpected] byte bits)
	{
		Vector256<short> y = Avx2.MultiplyHighRoundScale(x, Vector256.Create(multiplier));
		Vector256<short> remainder = (x << bits) - y * Vector256.Create(Q);
		y -= Vector256.GreaterThan(remainder, Vector256.Create((short)(Q / 2)));
		y += Vector256.GreaterThan(Vector256.Create((short)(-Q / 2)), remainder);
		return y & Vector256.Create((short)((1 << bits) - 1));
	}

	// Compress_1(x) is 1 exactly when |x| lies in [833, 2496]; t = |x| − 833 makes t | (1663 − t) negative exactly outside.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Compress1(ref short source, ref byte destination)
	{
		for (nint i = 0; i < 8; ++i)
		{
			Vector256<short> first = Vector256.Abs(Vector256.LoadUnsafe(ref source, (nuint)(32 * i))) - Vector256.Create((short)833);
			Vector256<short> second = Vector256.Abs(Vector256.LoadUnsafe(ref source, (nuint)(32 * i + 16))) - Vector256.Create((short)833);
			first |= Vector256.Create((short)1663) - first;
			second |= Vector256.Create((short)1663) - second;
			Vector256<long> outside = Avx2.PackSignedSaturate(first, second).AsInt64();
			uint bits = ~Vector256.ExtractMostSignificantBits(Avx2.Permute4x64(outside, 0b11_01_10_00).AsByte());
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 4 * i), bits);
		}
	}

	// Four vectors make 32 bytes.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Compress4(ref short source, ref byte destination)
	{
		Vector256<sbyte> nibbles = Vector256.Create((short)(1 | 16 << 8)).AsSByte();

		for (nint i = 0; i < 4; ++i)
		{
			ref short block = ref Unsafe.Add(ref source, 64 * i);
			Vector256<short> y0 = CompressValues(Vector256.LoadUnsafe(ref block), 157, 4);
			Vector256<short> y1 = CompressValues(Vector256.LoadUnsafe(ref block, 16), 157, 4);
			Vector256<short> y2 = CompressValues(Vector256.LoadUnsafe(ref block, 32), 157, 4);
			Vector256<short> y3 = CompressValues(Vector256.LoadUnsafe(ref block, 48), 157, 4);
			Vector256<short> first = Avx2.MultiplyAddAdjacent(Avx2.PackUnsignedSaturate(y0, y1), nibbles);
			Vector256<short> second = Avx2.MultiplyAddAdjacent(Avx2.PackUnsignedSaturate(y2, y3), nibbles);
			Vector256<int> packed = Avx2.PackUnsignedSaturate(first, second).AsInt32();
			Avx2.PermuteVar8x32(packed, Vector256.Create(0, 4, 1, 5, 2, 6, 3, 7)).AsByte().StoreUnsafe(ref destination, (nuint)(32 * i));
		}
	}

	// Two vectors make 20 bytes.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Compress5(ref short source, ref byte destination)
	{
		for (nint i = 0; i < 7; ++i)
		{
			Vector256<byte> chunks = Compress5(ref Unsafe.Add(ref source, 32 * i));
			chunks.GetLower().StoreUnsafe(ref destination, (nuint)(20 * i));
			chunks.GetUpper().StoreUnsafe(ref destination, (nuint)(20 * i + 10));
		}

		Vector256<byte> last = Compress5(ref Unsafe.Add(ref source, 224));
		last.GetLower().StoreUnsafe(ref destination, 140);
		StoreChunk(ref Unsafe.Add(ref destination, 150), last.GetUpper(), 2);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> Compress5(ref short source)
	{
		Vector256<short> y0 = CompressValues(Vector256.LoadUnsafe(ref source), 315, 5);
		Vector256<short> y1 = CompressValues(Vector256.LoadUnsafe(ref source, 16), 315, 5);
		Vector256<short> tens = Avx2.MultiplyAddAdjacent(Avx2.PackUnsignedSaturate(y0, y1), Vector256.Create((short)(1 | 32 << 8)).AsSByte());
		Vector256<int> twenties = Avx2.MultiplyAddAdjacent(tens, Vector256.Create(1 | 1024 << 16).AsInt16());
		Vector256<ulong> forties = Avx2.Permute4x64(JoinPairs(twenties, 20), 0b11_01_10_00);
		return Avx2.Shuffle(forties.AsByte(), FortyBitChunks);
	}

	// One vector makes 20 bytes, ten from each 128-bit lane.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Compress10(ref short source, ref byte destination)
	{
		for (nint i = 0; i < 15; ++i)
		{
			Vector256<byte> chunks = Compress10(Vector256.LoadUnsafe(ref source, (nuint)(16 * i)));
			chunks.GetLower().StoreUnsafe(ref destination, (nuint)(20 * i));
			chunks.GetUpper().StoreUnsafe(ref destination, (nuint)(20 * i + 10));
		}

		Vector256<byte> last = Compress10(Vector256.LoadUnsafe(ref source, 240));
		last.GetLower().StoreUnsafe(ref destination, 300);
		StoreChunk(ref Unsafe.Add(ref destination, 310), last.GetUpper(), 2);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> Compress10(Vector256<short> x)
	{
		Vector256<int> twenties = Avx2.MultiplyAddAdjacent(CompressValues(x, 10079, 10), Vector256.Create(1 | 1024 << 16).AsInt16());
		return Avx2.Shuffle(JoinPairs(twenties, 20).AsByte(), FortyBitChunks);
	}

	// One vector makes 22 bytes, eleven from each 128-bit lane; the two 44-bit units share a byte.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Compress11(ref short source, ref byte destination)
	{
		for (nint i = 0; i < 15; ++i)
		{
			Vector256<byte> chunks = Compress11(Vector256.LoadUnsafe(ref source, (nuint)(16 * i)));
			chunks.GetLower().StoreUnsafe(ref destination, (nuint)(22 * i));
			chunks.GetUpper().StoreUnsafe(ref destination, (nuint)(22 * i + 11));
		}

		Vector256<byte> last = Compress11(Vector256.LoadUnsafe(ref source, 240));
		last.GetLower().StoreUnsafe(ref destination, 330);
		StoreChunk(ref Unsafe.Add(ref destination, 341), last.GetUpper(), 3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> Compress11(Vector256<short> x)
	{
		Vector256<int> pairs = Avx2.MultiplyAddAdjacent(CompressValues(x, 20159, 11), Vector256.Create(1 | 2048 << 16).AsInt16());
		Vector256<ulong> shifted = Avx2.ShiftLeftLogicalVariable(pairs.AsUInt32(), Vector256.Create(10UL).AsUInt32()).AsUInt64();
		Vector256<byte> units = Avx2.ShiftRightLogicalVariable(shifted, Vector256.Create(10UL, 6, 10, 6)).AsByte();
		Vector256<byte> body = Avx2.Shuffle(units, Vector256.Create(Vector128.Create(0, 1, 2, 3, 4, 5, 9, 10, 11, 12, 13, 0x80, 0x80, 0x80, 0x80, 0x80)));
		Vector256<byte> seam = Avx2.Shuffle(units, Vector256.Create(Vector128.Create(0x80, 0x80, 0x80, 0x80, 0x80, 8, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80)));
		return body | seam;
	}

	// w0 | w1 << bits in each 64-bit lane from the 32-bit lanes w0, w1 below 2^bits.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> JoinPairs(Vector256<int> pairs, [ConstantExpected] byte bits)
	{
		Vector256<uint> raised = Avx2.ShiftLeftLogicalVariable(pairs.AsUInt32(), Vector256.Create((ulong)(32 - bits)).AsUInt32());
		return raised.AsUInt64() >>> 32 - bits;
	}

	// The five low bytes of each 64-bit unit, ten to a 128-bit lane.
	private static Vector256<byte> FortyBitChunks => Vector256.Create(Vector128.Create(0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80));

	// The first 8 + excess bytes of chunk as two overlapping 8-byte stores.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreChunk(ref byte destination, Vector128<byte> chunk, [ConstantExpected(Min = 1, Max = 7)] byte excess)
	{
		Unsafe.WriteUnaligned(ref destination, chunk.AsUInt64().ToScalar());
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, excess), Sse2.ShiftRightLogical128BitLane(chunk, excess).AsUInt64().ToScalar());
	}

	// Decompress_d(y) is the rounded product of y · 2^(12 − d) and 8q over 2^15, so the decoders below place each field at bit 12 − d.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<short> DecompressValues(Vector256<short> shifted)
	{
		return Avx2.MultiplyHighRoundScale(shifted, Vector256.Create((short)(8 * Q)));
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Decompress1(ref byte source, ref short destination)
	{
		Vector256<short> bits = Vector256.Create(1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, short.MinValue);

		for (nint i = 0; i < 16; ++i)
		{
			Vector256<short> set = Vector256.Equals(Vector256.Create(Unsafe.ReadUnaligned<short>(ref Unsafe.Add(ref source, 2 * i))) & bits, bits);
			(set & Vector256.Create((short)((Q + 1) / 2))).StoreUnsafe(ref destination, (nuint)(16 * i));
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Decompress4(ref byte source, ref short destination)
	{
		Vector256<byte> fields = Vector256.Create(0, 0x80, 0, 0x80, 1, 0x80, 1, 0x80, 2, 0x80, 2, 0x80, 3, 0x80, 3, 0x80, 4, 0x80, 4, 0x80, 5, 0x80, 5, 0x80, 6, 0x80, 6, 0x80, 7, 0x80, 7, 0x80);

		for (nint i = 0; i < 16; ++i)
		{
			Vector256<byte> bytes = Vector256.Create(Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref source, 8 * i))).AsByte();
			Vector256<short> shifted = Avx2.Shuffle(bytes, fields).AsInt16() * Vector256.Create(256 | 16 << 16).AsInt16() & Vector256.Create((short)0x0F00);
			DecompressValues(shifted).StoreUnsafe(ref destination, (nuint)(16 * i));
		}
	}

	// Ten bytes per vector, as 8 from its start and 8 ending at its end.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Decompress5(ref byte source, ref short destination)
	{
		Vector256<byte> fields = Vector256.Create(0, 0x80, 0, 1, 1, 0x80, 1, 2, 2, 3, 3, 0x80, 3, 4, 4, 0x80, 3, 0x80, 3, 4, 4, 0x80, 4, 5, 5, 6, 6, 0x80, 6, 7, 7, 0x80);
		Vector256<short> shifts = Vector256.Create(128, 4, 32, 1, 8, 64, 2, 16, 128, 4, 32, 1, 8, 64, 2, 16);

		for (nint i = 0; i < 16; ++i)
		{
			ref byte block = ref Unsafe.Add(ref source, 10 * i);
			Vector128<ulong> low = Vector128.CreateScalarUnsafe(Unsafe.ReadUnaligned<ulong>(ref block));
			Vector128<ulong> high = Vector128.CreateScalarUnsafe(Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref block, 2)));
			Vector256<short> shifted = Avx2.Shuffle(Vector256.Create(low, high).AsByte(), fields).AsInt16() * shifts & Vector256.Create((short)0x0F80);
			DecompressValues(shifted).StoreUnsafe(ref destination, (nuint)(16 * i));
		}
	}

	// Twenty bytes per vector, as 16 from its start and 16 ending at its end.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Decompress10(ref byte source, ref short destination)
	{
		Vector256<byte> fields = Vector256.Create((byte)0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 6, 7, 7, 8, 8, 9, 6, 7, 7, 8, 8, 9, 9, 10, 11, 12, 12, 13, 13, 14, 14, 15);
		Vector256<ushort> shifts = Vector256.Create((ushort)64, 16, 4, 1, 64, 16, 4, 1, 64, 16, 4, 1, 64, 16, 4, 1);

		for (nint i = 0; i < 16; ++i)
		{
			Vector256<byte> window = Vector256.Create(Vector128.LoadUnsafe(ref source, (nuint)(20 * i)), Vector128.LoadUnsafe(ref source, (nuint)(20 * i + 4)));
			Vector256<ushort> shifted = Avx2.Shuffle(window, fields).AsUInt16() * shifts >>> 4 & Vector256.Create((ushort)0x0FFC);
			DecompressValues(shifted.AsInt16()).StoreUnsafe(ref destination, (nuint)(16 * i));
		}
	}

	// Twenty-two bytes per vector, as 16 from its start and 16 ending at its end. An 11-bit field spans up to three bytes, so it is
	// shifted within a 32-bit lane.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Decompress11(ref byte source, ref short destination)
	{
		Vector256<byte> firstFields = Vector256.Create(0x80, 0, 1, 0x80, 0, 1, 2, 0x80, 1, 2, 3, 4, 3, 4, 5, 0x80, 4, 5, 6, 0x80, 5, 6, 7, 0x80, 6, 7, 8, 9, 8, 9, 10, 0x80);
		Vector256<byte> secondFields = Vector256.Create(4, 5, 6, 0x80, 5, 6, 7, 8, 7, 8, 9, 0x80, 8, 9, 10, 0x80, 9, 10, 11, 0x80, 10, 11, 12, 13, 12, 13, 14, 0x80, 13, 14, 15, 0x80);
		Vector256<uint> firstShifts = Vector256.Create(7u, 10, 13, 8, 7, 10, 13, 8);
		Vector256<uint> secondShifts = Vector256.Create(11u, 14, 9, 12, 11, 14, 9, 12);
		Vector256<uint> mask = Vector256.Create(0x0FFEu);

		for (nint i = 0; i < 16; ++i)
		{
			Vector256<byte> window = Vector256.Create(Vector128.LoadUnsafe(ref source, (nuint)(22 * i)), Vector128.LoadUnsafe(ref source, (nuint)(22 * i + 6)));
			Vector256<uint> first = Avx2.ShiftRightLogicalVariable(Avx2.Shuffle(window, firstFields).AsUInt32(), firstShifts) & mask;
			Vector256<uint> second = Avx2.ShiftRightLogicalVariable(Avx2.Shuffle(window, secondFields).AsUInt32(), secondShifts) & mask;
			DecompressValues(Avx2.PackUnsignedSaturate(first.AsInt32(), second.AsInt32()).AsInt16()).StoreUnsafe(ref destination, (nuint)(16 * i));
		}
	}

	// a + 2 − b in each nibble never borrows from the next.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void SampleCbd2(ref byte source, ref short destination)
	{
		for (nint i = 0; i < 4; ++i)
		{
			Vector256<byte> bits = Vector256.LoadUnsafe(ref source, (nuint)(32 * i));
			Vector256<byte> counts = (bits & Vector256.Create((byte)0x55)) + ((bits.AsUInt16() >>> 1).AsByte() & Vector256.Create((byte)0x55));
			Vector256<byte> differences = (counts & Vector256.Create((byte)0x33)) + Vector256.Create((byte)0x22) - ((counts.AsUInt16() >>> 2).AsByte() & Vector256.Create((byte)0x33));
			Vector256<sbyte> low = (differences & Vector256.Create((byte)0x0F)).AsSByte() - Vector256.Create((sbyte)2);
			Vector256<sbyte> high = ((differences.AsUInt16() >>> 4).AsByte() & Vector256.Create((byte)0x0F)).AsSByte() - Vector256.Create((sbyte)2);
			Vector256<sbyte> first = Avx2.UnpackLow(low, high);
			Vector256<sbyte> second = Avx2.UnpackHigh(low, high);
			ref short block = ref Unsafe.Add(ref destination, 64 * i);
			Avx2.ConvertToVector256Int16(first.GetLower()).StoreUnsafe(ref block);
			Avx2.ConvertToVector256Int16(second.GetLower()).StoreUnsafe(ref block, 16);
			Avx2.ConvertToVector256Int16(first.GetUpper()).StoreUnsafe(ref block, 32);
			Avx2.ConvertToVector256Int16(second.GetUpper()).StoreUnsafe(ref block, 48);
		}
	}

	// 32 coefficients per 24 bytes, read as in Decode12; a + 3 − b in each 6-bit field never borrows.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void SampleCbd3(ref byte source, ref short destination)
	{
		Vector256<byte> groups = Vector256.Create(0, 1, 2, 0x80, 3, 4, 5, 0x80, 6, 7, 8, 0x80, 9, 10, 11, 0x80, 4, 5, 6, 0x80, 7, 8, 9, 0x80, 10, 11, 12, 0x80, 13, 14, 15, 0x80);
		Vector256<byte> fields = Vector256.Create((byte)0, 1, 0, 1, 1, 2, 2, 3, 4, 5, 4, 5, 5, 6, 6, 7, 8, 9, 8, 9, 9, 10, 10, 11, 12, 13, 12, 13, 13, 14, 14, 15);
		Vector256<ushort> shifts = Vector256.Create((ushort)8192, 128, 512, 2048, 8192, 128, 512, 2048, 8192, 128, 512, 2048, 8192, 128, 512, 2048);
		Vector256<uint> ones = Vector256.Create(0x249249u);
		Vector256<uint> fieldMask = Vector256.Create(0x1C71C7u);

		for (nint i = 0; i < 8; ++i)
		{
			Vector256<byte> window = Vector256.Create(Vector128.LoadUnsafe(ref source, (nuint)(24 * i)), Vector128.LoadUnsafe(ref source, (nuint)(24 * i + 8)));
			Vector256<uint> bits = Avx2.Shuffle(window, groups).AsUInt32();
			Vector256<uint> counts = (bits & ones) + (bits >>> 1 & ones) + (bits >>> 2 & ones);
			Vector256<uint> differences = (counts & fieldMask) + Vector256.Create(0xC30C3u) - (counts >>> 3 & fieldMask);
			ref short block = ref Unsafe.Add(ref destination, 32 * i);
			SampleCbd3Spread(Avx2.Permute4x64(differences.AsUInt64(), 0b01_00_01_00).AsByte(), fields, shifts).StoreUnsafe(ref block);
			SampleCbd3Spread(Avx2.Permute4x64(differences.AsUInt64(), 0b11_10_11_10).AsByte(), fields, shifts).StoreUnsafe(ref block, 16);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<short> SampleCbd3Spread(Vector256<byte> differences, Vector256<byte> fields, Vector256<ushort> shifts)
	{
		Vector256<ushort> raised = Avx2.Shuffle(differences, fields).AsUInt16() * shifts;
		return (raised >>> 13).AsInt16() - Vector256.Create((short)3);
	}
}
