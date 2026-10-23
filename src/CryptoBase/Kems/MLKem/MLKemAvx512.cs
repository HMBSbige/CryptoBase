using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Kems.MLKem;

// Thirty-two coefficients per 512-bit vector, as in MLKemAvx2. IsSupported requires Vector512.IsHardwareAccelerated too, which the
// runtime reports false where it prefers 256-bit vectors.
internal readonly partial struct MLKemAvx512 : IMLKemKernel
{
	private const int N = MLKemConstants.N;
	private const short Q = MLKemConstants.Q;

	public static bool IsSupported => Avx512BW.IsSupported && Vector512.IsHardwareAccelerated;

	// The bounds are those of MLKemAvx2.Ntt.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void Ntt(Span<short> f)
	{
		Debug.Assert(f.Length is N);

		ref Vector512<short> coefficients = ref Unsafe.As<short, Vector512<short>>(ref MemoryMarshal.GetReference(f));
		ref Vector512<short> zetas = ref Unsafe.As<short, Vector512<short>>(ref MemoryMarshal.GetReference(NttZetas));
		Vector512<short> v0 = coefficients;
		Vector512<short> v1 = Unsafe.Add(ref coefficients, 1);
		Vector512<short> v2 = Unsafe.Add(ref coefficients, 2);
		Vector512<short> v3 = Unsafe.Add(ref coefficients, 3);
		Vector512<short> v4 = Unsafe.Add(ref coefficients, 4);
		Vector512<short> v5 = Unsafe.Add(ref coefficients, 5);
		Vector512<short> v6 = Unsafe.Add(ref coefficients, 6);
		Vector512<short> v7 = Unsafe.Add(ref coefficients, 7);

		Butterfly(ref v0, ref v4, ref zetas);
		Butterfly(ref v1, ref v5, ref zetas);
		Butterfly(ref v2, ref v6, ref zetas);
		Butterfly(ref v3, ref v7, ref zetas);

		Butterfly(ref v0, ref v2, ref Unsafe.Add(ref zetas, 2));
		Butterfly(ref v1, ref v3, ref Unsafe.Add(ref zetas, 2));
		Butterfly(ref v4, ref v6, ref Unsafe.Add(ref zetas, 4));
		Butterfly(ref v5, ref v7, ref Unsafe.Add(ref zetas, 4));

		Butterfly(ref v0, ref v1, ref Unsafe.Add(ref zetas, 6));
		Butterfly(ref v2, ref v3, ref Unsafe.Add(ref zetas, 8));
		Butterfly(ref v4, ref v5, ref Unsafe.Add(ref zetas, 10));
		Butterfly(ref v6, ref v7, ref Unsafe.Add(ref zetas, 12));

		NttPair(v0, v1, ref Unsafe.Add(ref zetas, 14), out coefficients);
		NttPair(v2, v3, ref Unsafe.Add(ref zetas, 22), out Unsafe.Add(ref coefficients, 2));
		NttPair(v4, v5, ref Unsafe.Add(ref zetas, 30), out Unsafe.Add(ref coefficients, 4));
		NttPair(v6, v7, ref Unsafe.Add(ref zetas, 38), out Unsafe.Add(ref coefficients, 6));
	}

	// The mirror of Ntt, reducing the sums of layers 3 and 6 as MLKemAvx2.InverseNtt does.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void InverseNtt(Span<short> f)
	{
		Debug.Assert(f.Length is N);

		ref Vector512<short> coefficients = ref Unsafe.As<short, Vector512<short>>(ref MemoryMarshal.GetReference(f));
		ref Vector512<short> zetas = ref Unsafe.As<short, Vector512<short>>(ref MemoryMarshal.GetReference(InverseNttZetas));

		InverseNttPair(ref coefficients, ref zetas, out Vector512<short> v0, out Vector512<short> v1);
		InverseNttPair(ref Unsafe.Add(ref coefficients, 2), ref Unsafe.Add(ref zetas, 8), out Vector512<short> v2, out Vector512<short> v3);
		InverseNttPair(ref Unsafe.Add(ref coefficients, 4), ref Unsafe.Add(ref zetas, 16), out Vector512<short> v4, out Vector512<short> v5);
		InverseNttPair(ref Unsafe.Add(ref coefficients, 6), ref Unsafe.Add(ref zetas, 24), out Vector512<short> v6, out Vector512<short> v7);

		InverseButterfly(ref v0, ref v1, ref Unsafe.Add(ref zetas, 32));
		InverseButterfly(ref v2, ref v3, ref Unsafe.Add(ref zetas, 34));
		InverseButterfly(ref v4, ref v5, ref Unsafe.Add(ref zetas, 36));
		InverseButterfly(ref v6, ref v7, ref Unsafe.Add(ref zetas, 38));

		InverseButterfly(ref v0, ref v2, ref Unsafe.Add(ref zetas, 40));
		InverseButterfly(ref v1, ref v3, ref Unsafe.Add(ref zetas, 40));
		InverseButterfly(ref v4, ref v6, ref Unsafe.Add(ref zetas, 42));
		InverseButterfly(ref v5, ref v7, ref Unsafe.Add(ref zetas, 42));
		v0 = Reduce(v0);
		v1 = Reduce(v1);
		v4 = Reduce(v4);
		v5 = Reduce(v5);

		LastInverseButterfly(v0, v4, out coefficients, out Unsafe.Add(ref coefficients, 4));
		LastInverseButterfly(v1, v5, out Unsafe.Add(ref coefficients, 1), out Unsafe.Add(ref coefficients, 5));
		LastInverseButterfly(v2, v6, out Unsafe.Add(ref coefficients, 2), out Unsafe.Add(ref coefficients, 6));
		LastInverseButterfly(v3, v7, out Unsafe.Add(ref coefficients, 3), out Unsafe.Add(ref coefficients, 7));
	}

	// MLKemAvx2.MultiplyAccumulate on 512-bit vectors.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void MultiplyAccumulate(ReadOnlySpan<short> a, int aStride, ReadOnlySpan<short> b, Span<short> destination, int count)
	{
		Debug.Assert(count is >= 1 and <= 4);
		Debug.Assert(aStride >= N && a.Length >= (count - 1) * aStride + N && b.Length >= count * N && destination.Length is N);

		ref short x = ref MemoryMarshal.GetReference(a);
		ref short y = ref MemoryMarshal.GetReference(b);
		ref short z = ref MemoryMarshal.GetReference(destination);
		ref short deltas = ref MemoryMarshal.GetReference(MLKemAvx2.MultiplyDeltas);
		Vector512<int> oddMask = Vector512.Create(unchecked((int)0xFFFF0000));

		for (nint i = 0; i < N; i += 32)
		{
			Vector512<int> sums = Vector512<int>.Zero;
			Vector512<int> oddProducts = Vector512<int>.Zero;
			Vector512<int> crossSums = Vector512<int>.Zero;
			ref short left = ref Unsafe.Add(ref x, i);
			ref short right = ref Unsafe.Add(ref y, i);

			for (int j = 0; j < count; ++j)
			{
				Vector512<short> u = Vector512.LoadUnsafe(ref left);
				Vector512<short> v = Vector512.LoadUnsafe(ref right);
				sums += Avx512BW.MultiplyAddAdjacent(u, v);
				oddProducts += Avx512BW.MultiplyAddAdjacent(u, (v.AsInt32() & oddMask).AsInt16());
				crossSums += Avx512BW.MultiplyAddAdjacent(u, Avx512F.RotateLeft(v.AsUInt32(), 16).AsInt16());
				left = ref Unsafe.Add(ref left, aStride);
				right = ref Unsafe.Add(ref right, N);
			}

			Vector512<int> evenSums = sums + Avx512BW.MultiplyAddAdjacent(MontgomeryReduce(oddProducts).AsInt16(), Vector512.LoadUnsafe(ref deltas, (nuint)i));
			(MontgomeryReduce(evenSums) >>> 16 | MontgomeryReduce(crossSums)).AsInt16().StoreUnsafe(ref z, (nuint)i);
		}
	}

	// A 512-bit Reduce is faster on its own, but it makes Encrypt spill 512-bit registers around calls and is no faster end to end, so it runs on 256-bit vectors.
	public static void Reduce(Span<short> f)
	{
		MLKemAvx2.Reduce(f);
	}

	public static void ToMontgomery(Span<short> f)
	{
		Debug.Assert(f.Length is N);

		ref short coefficients = ref MemoryMarshal.GetReference(f);

		for (nuint i = 0; i < N; i += 32)
		{
			Vector512<short> value = Vector512.LoadUnsafe(ref coefficients, i);
			MultiplyMontgomery(value, Vector512.Create(MLKemConstants.RSquared), Vector512.Create(MLKemConstants.RSquaredQInverse)).StoreUnsafe(ref coefficients, i);
		}
	}

	public static void Add(ReadOnlySpan<short> left, ReadOnlySpan<short> right, Span<short> destination)
	{
		Debug.Assert(left.Length is N && right.Length is N && destination.Length is N);

		ref short x = ref MemoryMarshal.GetReference(left);
		ref short y = ref MemoryMarshal.GetReference(right);
		ref short z = ref MemoryMarshal.GetReference(destination);

		for (nuint i = 0; i < N; i += 32)
		{
			(Vector512.LoadUnsafe(ref x, i) + Vector512.LoadUnsafe(ref y, i)).StoreUnsafe(ref z, i);
		}
	}

	public static void Subtract(ReadOnlySpan<short> left, ReadOnlySpan<short> right, Span<short> destination)
	{
		Debug.Assert(left.Length is N && right.Length is N && destination.Length is N);

		ref short x = ref MemoryMarshal.GetReference(left);
		ref short y = ref MemoryMarshal.GetReference(right);
		ref short z = ref MemoryMarshal.GetReference(destination);

		for (nuint i = 0; i < N; i += 32)
		{
			(Vector512.LoadUnsafe(ref x, i) - Vector512.LoadUnsafe(ref y, i)).StoreUnsafe(ref z, i);
		}
	}

	// Thirty-two coefficients make 48 bytes, written with 64-byte stores that the next one overwrites, but for the last.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void Encode12(ReadOnlySpan<short> f, Span<byte> destination)
	{
		Debug.Assert(f.Length is N && destination.Length >= 384);

		ref short source = ref MemoryMarshal.GetReference(f);
		ref byte target = ref MemoryMarshal.GetReference(destination);

		for (nint i = 0; i < 7; ++i)
		{
			Encode12(Vector512.LoadUnsafe(ref source, (nuint)(32 * i))).StoreUnsafe(ref target, (nuint)(48 * i));
		}

		Vector512<byte> last = Encode12(Vector512.LoadUnsafe(ref source, 224));
		last.GetLower().StoreUnsafe(ref target, 336);
		last.GetUpper().GetLower().StoreUnsafe(ref target, 368);
	}

	// As MLKemAvx2.Decode12, each 128-bit lane taking its 12 bytes with a permutation.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static bool Decode12(ReadOnlySpan<byte> source, Span<short> f)
	{
		Debug.Assert(source.Length >= 384 && f.Length is N);

		ref byte input = ref MemoryMarshal.GetReference(source);
		ref short output = ref MemoryMarshal.GetReference(f);
		Vector512<ushort> largest = Vector512<ushort>.Zero;

		for (int i = 0; i < 8; ++i)
		{
			Vector512<ushort> values = Decode12(Groups(ref input, 48 * i, 384));
			largest = Vector512.Max(largest, values);
			values.AsInt16().StoreUnsafe(ref output, (nuint)(32 * i));
		}

		return Vector512.LessThanAll(largest, Vector512.Create((ushort)Q));
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

	// Without AVX512-VBMI2 for the compression, MLKemAvx2.RejectSample does the work.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static unsafe int RejectSample(ReadOnlySpan<byte> source, Span<short> destination)
	{
		if (!Avx512Vbmi2.IsSupported)
		{
			return MLKemAvx2.RejectSample(source, destination);
		}

		Debug.Assert(source.Length % 3 is 0);

		const int GroupLength = 48;
		Vector512<int> groups = Vector512.Create(0, 1, 2, 0, 3, 4, 5, 0, 6, 7, 8, 0, 9, 10, 11, 0);
		Vector512<short> lanes = Vector512.Create(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31);
		int count = 0;
		int offset = 0;

		fixed (byte* input = source)
		fixed (short* output = destination)
		{
			for (; offset <= source.Length - GroupLength && count < destination.Length; offset += GroupLength)
			{
				Vector512<byte> bytes = offset <= source.Length - Vector512<byte>.Count
					? Vector512.Load(input + offset)
					: Avx512BW.MaskLoad(input + offset, Vector512.LessThan(Vector512<byte>.Indices, Vector512.Create((byte)GroupLength)), Vector512<byte>.Zero);
				Vector512<short> candidates = Decode12(Avx512F.PermuteVar16x32(bytes.AsInt32(), groups)).AsInt16();
				Vector512<short> accepted = Vector512.LessThan(candidates, Vector512.Create(Q));
				Vector512<short> packed = Avx512Vbmi2.Compress(Vector512<short>.Zero, accepted, candidates);
				int written = Math.Min(BitOperations.PopCount(accepted.ExtractMostSignificantBits()), destination.Length - count);
				Avx512BW.MaskStore(output + count, Vector512.LessThan(lanes, Vector512.Create((short)written)), packed);
				count += written;
			}
		}

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

	// Layers 4 to 7 of NTT on the 64 coefficients of a and b, written back in order to destination.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void NttPair(Vector512<short> a, Vector512<short> b, ref Vector512<short> zetas, out Vector512<short> destination)
	{
		Vector512<short> low = Avx512F.Shuffle4x128(a.AsInt64(), b.AsInt64(), 0b01_00_01_00).AsInt16();
		Vector512<short> high = Avx512F.Shuffle4x128(a.AsInt64(), b.AsInt64(), 0b11_10_11_10).AsInt16();
		Butterfly(ref low, ref high, ref zetas);

		a = Avx512F.Shuffle4x128(low.AsInt64(), high.AsInt64(), 0b10_00_10_00).AsInt16();
		b = Avx512F.Shuffle4x128(low.AsInt64(), high.AsInt64(), 0b11_01_11_01).AsInt16();
		Butterfly(ref a, ref b, ref Unsafe.Add(ref zetas, 2));

		low = Avx512F.UnpackLow(a.AsInt64(), b.AsInt64()).AsInt16();
		high = Avx512F.UnpackHigh(a.AsInt64(), b.AsInt64()).AsInt16();
		Butterfly(ref low, ref high, ref Unsafe.Add(ref zetas, 4));

		a = Avx512F.Shuffle(low.AsSingle(), high.AsSingle(), 0b10_00_10_00).AsInt16();
		b = Avx512F.Shuffle(low.AsSingle(), high.AsSingle(), 0b11_01_11_01).AsInt16();
		Butterfly(ref a, ref b, ref Unsafe.Add(ref zetas, 6));
		a = Reduce(a);
		b = Reduce(b);

		destination = Avx512F.PermuteVar16x32x2(a.AsInt32(), Vector512.Create(0, 16, 2, 18, 1, 17, 3, 19, 8, 24, 10, 26, 9, 25, 11, 27), b.AsInt32()).AsInt16();
		Unsafe.Add(ref destination, 1) = Avx512F.PermuteVar16x32x2(a.AsInt32(), Vector512.Create(4, 20, 6, 22, 5, 21, 7, 23, 12, 28, 14, 30, 13, 29, 15, 31), b.AsInt32()).AsInt16();
	}

	// Layers 1 to 4 of NTT⁻¹ on the 64 coefficients at source, undoing the moves of NttPair.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseNttPair(ref Vector512<short> source, ref Vector512<short> zetas, out Vector512<short> first, out Vector512<short> second)
	{
		Vector512<int> a = source.AsInt32();
		Vector512<int> b = Unsafe.Add(ref source, 1).AsInt32();
		Vector512<short> low = Avx512F.PermuteVar16x32x2(a, Vector512.Create(0, 4, 2, 6, 16, 20, 18, 22, 8, 12, 10, 14, 24, 28, 26, 30), b).AsInt16();
		Vector512<short> high = Avx512F.PermuteVar16x32x2(a, Vector512.Create(1, 5, 3, 7, 17, 21, 19, 23, 9, 13, 11, 15, 25, 29, 27, 31), b).AsInt16();
		InverseButterfly(ref low, ref high, ref zetas);

		Vector512<short> c = Avx512F.UnpackLow(low.AsInt32(), high.AsInt32()).AsInt16();
		Vector512<short> d = Avx512F.UnpackHigh(low.AsInt32(), high.AsInt32()).AsInt16();
		InverseButterfly(ref c, ref d, ref Unsafe.Add(ref zetas, 2));

		low = Avx512F.UnpackLow(c.AsInt64(), d.AsInt64()).AsInt16();
		high = Avx512F.UnpackHigh(c.AsInt64(), d.AsInt64()).AsInt16();
		InverseButterfly(ref low, ref high, ref Unsafe.Add(ref zetas, 4));
		low = Reduce(low);

		c = Avx512F.PermuteVar8x64x2(low.AsInt64(), Vector512.Create(0L, 1, 8, 9, 2, 3, 10, 11), high.AsInt64()).AsInt16();
		d = Avx512F.PermuteVar8x64x2(low.AsInt64(), Vector512.Create(4L, 5, 12, 13, 6, 7, 14, 15), high.AsInt64()).AsInt16();
		InverseButterfly(ref c, ref d, ref Unsafe.Add(ref zetas, 6));

		first = Avx512F.Shuffle4x128(c.AsInt64(), d.AsInt64(), 0b01_00_01_00).AsInt16();
		second = Avx512F.Shuffle4x128(c.AsInt64(), d.AsInt64(), 0b11_10_11_10).AsInt16();
	}

	// Layer 7 of NTT⁻¹ with the factor that ends it.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LastInverseButterfly(Vector512<short> x, Vector512<short> y, out Vector512<short> low, out Vector512<short> high)
	{
		low = MultiplyMontgomery(x + y, Vector512.Create(MLKemConstants.InverseNttFactor), Vector512.Create(MLKemConstants.InverseNttFactorQInverse));
		high = MultiplyMontgomery(y - x, Vector512.Create(MLKemConstants.LastInverseZeta), Vector512.Create(MLKemConstants.LastInverseZetaQInverse));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Butterfly(ref Vector512<short> x, ref Vector512<short> y, ref Vector512<short> zeta)
	{
		Vector512<short> t = MultiplyMontgomery(y, zeta, Unsafe.Add(ref zeta, 1));
		y = x - t;
		x += t;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseButterfly(ref Vector512<short> x, ref Vector512<short> y, ref Vector512<short> zeta)
	{
		Vector512<short> difference = y - x;
		x += y;
		y = MultiplyMontgomery(difference, zeta, Unsafe.Add(ref zeta, 1));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<short> MultiplyMontgomery(Vector512<short> a, Vector512<short> b, Vector512<short> bQInverse)
	{
		Vector512<short> high = Avx512BW.MultiplyHigh(a, b);
		Vector512<short> t = a * bQInverse;
		return high - Avx512BW.MultiplyHigh(t, Vector512.Create(Q));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<int> MontgomeryReduce(Vector512<int> a)
	{
		Vector512<short> t = a.AsInt16() * Vector512.Create(MLKemConstants.QInverse);
		return a - Avx512BW.MultiplyAddAdjacent(t, Vector512.Create((int)Q).AsInt16());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<short> Reduce(Vector512<short> a)
	{
		Vector512<short> quotient = Avx512BW.MultiplyHighRoundScale(a, Vector512.Create((short)10));
		return a - quotient * Vector512.Create(Q);
	}

	// The 48 bytes of ByteEncode_12 of 32 coefficients in (−q, q), then sixteen zeros.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<byte> Encode12(Vector512<short> x)
	{
		x += x >> 15 & Vector512.Create(Q);
		Vector512<int> pairs = Avx512BW.MultiplyAddAdjacent(x, Vector512.Create(1 | 4096 << 16).AsInt16());
		Vector512<byte> packed = Avx512BW.Shuffle(pairs.AsByte(), Encode12Bytes);
		return Avx512F.PermuteVar16x32(packed.AsInt32(), Vector512.Create(0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 3, 3, 3, 3)).AsByte();
	}

	// The 12-bit values of the 12 bytes at the start of each 128-bit lane.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ushort> Decode12(Vector512<int> groups)
	{
		return Avx512BW.Shuffle(groups.AsByte(), Decode12Fields).AsUInt16() * Vector512.Create(16 | 1 << 16).AsUInt16() >>> 4;
	}

	// MLKemAvx2.CompressValues on 512-bit vectors.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<short> CompressValues(Vector512<short> x, short multiplier, [ConstantExpected] byte bits)
	{
		Vector512<short> y = Avx512BW.MultiplyHighRoundScale(x, Vector512.Create(multiplier));
		Vector512<short> remainder = (x << bits) - y * Vector512.Create(Q);
		y -= Vector512.GreaterThan(remainder, Vector512.Create((short)(Q / 2)));
		y += Vector512.GreaterThan(Vector512.Create((short)(-Q / 2)), remainder);
		return y & Vector512.Create((short)((1 << bits) - 1));
	}

	// Four bytes per vector, the complements of the signs that MLKemAvx2.Compress1 computes.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Compress1(ref short source, ref byte destination)
	{
		for (nint i = 0; i < 8; ++i)
		{
			Vector512<short> t = Vector512.Abs(Vector512.LoadUnsafe(ref source, (nuint)(32 * i))) - Vector512.Create((short)833);
			t |= Vector512.Create((short)1663) - t;
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 4 * i), ~(uint)t.ExtractMostSignificantBits());
		}
	}

	// Sixteen bytes per vector.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Compress4(ref short source, ref byte destination)
	{
		for (nint i = 0; i < 8; ++i)
		{
			Vector512<uint> pairs = CompressValues(Vector512.LoadUnsafe(ref source, (nuint)(32 * i)), 157, 4).AsUInt32();
			Avx512F.ConvertToVector128Byte(pairs | pairs >>> 12).StoreUnsafe(ref destination, (nuint)(16 * i));
		}
	}

	// Two vectors make 40 bytes, written with 64-byte stores that the next one overwrites, but for the last.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Compress5(ref short source, ref byte destination)
	{
		for (nint i = 0; i < 3; ++i)
		{
			Compress5(ref Unsafe.Add(ref source, 64 * i)).StoreUnsafe(ref destination, (nuint)(40 * i));
		}

		Vector512<byte> last = Compress5(ref Unsafe.Add(ref source, 192));
		last.GetLower().StoreUnsafe(ref destination, 120);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 152), last.GetUpper().AsUInt64().ToScalar());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<byte> Compress5(ref short source)
	{
		Vector256<byte> low = Avx512BW.ConvertToVector256Byte(CompressValues(Vector512.LoadUnsafe(ref source), 315, 5).AsUInt16());
		Vector256<byte> high = Avx512BW.ConvertToVector256Byte(CompressValues(Vector512.LoadUnsafe(ref source, 32), 315, 5).AsUInt16());
		Vector512<short> tens = Avx512BW.MultiplyAddAdjacent(low.ToVector512Unsafe().WithUpper(high), Vector512.Create((short)(1 | 32 << 8)).AsSByte());
		Vector512<int> twenties = Avx512BW.MultiplyAddAdjacent(tens, Vector512.Create(1 | 1024 << 16).AsInt16());
		return JoinChunks(JoinPairs(twenties, 20));
	}

	// One vector makes 40 bytes, ten from each 128-bit lane, written as by Compress5.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Compress10(ref short source, ref byte destination)
	{
		for (nint i = 0; i < 7; ++i)
		{
			Compress10(Vector512.LoadUnsafe(ref source, (nuint)(32 * i))).StoreUnsafe(ref destination, (nuint)(40 * i));
		}

		Vector512<byte> last = Compress10(Vector512.LoadUnsafe(ref source, 224));
		last.GetLower().StoreUnsafe(ref destination, 280);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 312), last.GetUpper().AsUInt64().ToScalar());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<byte> Compress10(Vector512<short> x)
	{
		Vector512<int> twenties = Avx512BW.MultiplyAddAdjacent(CompressValues(x, 10079, 10), Vector512.Create(1 | 1024 << 16).AsInt16());
		return JoinChunks(JoinPairs(twenties, 20));
	}

	// One vector makes 44 bytes, written as by Compress5, eleven per 128-bit lane as in MLKemAvx2.Compress11.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Compress11(ref short source, ref byte destination)
	{
		for (nint i = 0; i < 7; ++i)
		{
			Compress11(Vector512.LoadUnsafe(ref source, (nuint)(32 * i))).StoreUnsafe(ref destination, (nuint)(44 * i));
		}

		Vector512<byte> last = Compress11(Vector512.LoadUnsafe(ref source, 224));
		Vector128<byte> tail = last.GetUpper().GetLower();
		last.GetLower().StoreUnsafe(ref destination, 308);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 340), tail.AsUInt64().ToScalar());
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 348), tail.AsUInt32().GetElement(2));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<byte> Compress11(Vector512<short> x)
	{
		Vector512<byte> bodies = Vector512.Create(0, 1, 2, 3, 4, 5, 9, 10, 11, 12, 13, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 1, 2, 3, 4, 5, 9, 10, 11, 12, 13, 0x80, 0x80, 0x80, 0x80, 0, 1, 2, 3, 4, 5, 9, 10, 11, 12, 13, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 1, 2, 3, 4, 5, 9, 10, 11, 12, 13, 0x80, 0x80, 0x80, 0x80);
		Vector512<byte> seams = Vector512.Create(0x80, 0x80, 0x80, 0x80, 0x80, 8, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 8, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 8, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 8, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80);
		Vector512<int> pairs = Avx512BW.MultiplyAddAdjacent(CompressValues(x, 20159, 11), Vector512.Create(1 | 2048 << 16).AsInt16());
		Vector512<ulong> shifted = Avx512F.ShiftLeftLogicalVariable(pairs.AsUInt32(), Vector512.Create(10UL).AsUInt32()).AsUInt64();
		Vector512<byte> units = Avx512F.ShiftRightLogicalVariable(shifted, Vector512.Create(10UL, 6, 10, 6, 10, 6, 10, 6)).AsByte();
		Vector512<short> lanes = (Avx512BW.Shuffle(units, bodies) | Avx512BW.Shuffle(units, seams)).AsInt16();
		Vector512<short> joined = Avx512BW.PermuteVar32x16(lanes, Vector512.Create(0, 1, 2, 3, 4, 5, 9, 10, 11, 12, 13, 16, 17, 18, 19, 20, 21, 25, 26, 27, 28, 29, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7));
		return (joined | Avx512BW.PermuteVar32x16(lanes, Vector512.Create(7, 7, 7, 7, 7, 8, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 24, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7))).AsByte();
	}

	// w0 | w1 << bits in each 64-bit lane from the 32-bit lanes w0, w1 below 2^bits.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> JoinPairs(Vector512<int> pairs, [ConstantExpected] byte bits)
	{
		Vector512<uint> raised = Avx512F.ShiftLeftLogicalVariable(pairs.AsUInt32(), Vector512.Create((ulong)(32 - bits)).AsUInt32());
		return raised.AsUInt64() >>> 32 - bits;
	}

	// The five low bytes of each 64-bit unit in order, as the first 40 bytes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<byte> JoinChunks(Vector512<ulong> forties)
	{
		Vector512<byte> chunks = Avx512BW.Shuffle(forties.AsByte(), Vector512.Create(0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80));
		return Avx512BW.PermuteVar32x16(chunks.AsInt16(), Vector512.Create(0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 16, 17, 18, 19, 20, 24, 25, 26, 27, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)).AsByte();
	}

	// MLKemAvx2.DecompressValues on 512-bit vectors.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<short> DecompressValues(Vector512<short> shifted)
	{
		return Avx512BW.MultiplyHighRoundScale(shifted, Vector512.Create((short)(8 * Q)));
	}

	// The load moves back near the end of length bytes to stay within them.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<byte> Windows(ref byte source, int start, [ConstantExpected] int length, Vector512<short> windows)
	{
		int offset = Math.Min(start, length - 64);
		Vector512<short> bytes = Vector512.LoadUnsafe(ref source, (nuint)offset).AsInt16();
		return Avx512BW.PermuteVar32x16(bytes, windows + Vector512.Create((short)(start - offset >> 1))).AsByte();
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Decompress1(ref byte source, ref short destination)
	{
		Vector512<ushort> bits = Vector512.Create(1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768);

		for (nint i = 0; i < 8; ++i)
		{
			ref byte block = ref Unsafe.Add(ref source, 4 * i);
			Vector512<ushort> spread = Vector256.Create(Unsafe.ReadUnaligned<ushort>(ref block)).ToVector512Unsafe().WithUpper(Vector256.Create(Unsafe.ReadUnaligned<ushort>(ref Unsafe.Add(ref block, 2))));
			(Vector512.Equals(spread & bits, bits).AsInt16() & Vector512.Create((short)((Q + 1) / 2))).StoreUnsafe(ref destination, (nuint)(32 * i));
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Decompress4(ref byte source, ref short destination)
	{
		for (nint i = 0; i < 8; ++i)
		{
			Vector512<uint> bytes = Avx512F.ConvertToVector512UInt32(Vector128.LoadUnsafe(ref source, (nuint)(16 * i)));
			Vector512<uint> shifted = (bytes << 8 | bytes << 20) & Vector512.Create(0x0F000F00u);
			DecompressValues(shifted.AsInt16()).StoreUnsafe(ref destination, (nuint)(32 * i));
		}
	}

	// Twenty bytes per vector, five per 128-bit lane, then as in MLKemAvx2.Decompress5.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Decompress5(ref byte source, ref short destination)
	{
		Vector512<short> windows = Vector512.Create(0, 1, 2, 3, 4, 5, 6, 7, 2, 3, 4, 5, 6, 7, 8, 9, 5, 6, 7, 8, 9, 10, 11, 12, 7, 8, 9, 10, 11, 12, 13, 14);
		Vector512<byte> fields = Vector512.Create(0, 0x80, 0, 1, 1, 0x80, 1, 2, 2, 3, 3, 0x80, 3, 4, 4, 0x80, 1, 0x80, 1, 2, 2, 0x80, 2, 3, 3, 4, 4, 0x80, 4, 5, 5, 0x80, 0, 0x80, 0, 1, 1, 0x80, 1, 2, 2, 3, 3, 0x80, 3, 4, 4, 0x80, 1, 0x80, 1, 2, 2, 0x80, 2, 3, 3, 4, 4, 0x80, 4, 5, 5, 0x80);
		Vector512<short> shifts = Vector512.Create(128, 4, 32, 1, 8, 64, 2, 16, 128, 4, 32, 1, 8, 64, 2, 16, 128, 4, 32, 1, 8, 64, 2, 16, 128, 4, 32, 1, 8, 64, 2, 16);

		for (int i = 0; i < 8; ++i)
		{
			Vector512<short> shifted = Avx512BW.Shuffle(Windows(ref source, 20 * i, 160, windows), fields).AsInt16() * shifts & Vector512.Create((short)0x0F80);
			DecompressValues(shifted).StoreUnsafe(ref destination, (nuint)(32 * i));
		}
	}

	// Forty bytes per vector, ten per 128-bit lane, then as in MLKemAvx2.Decompress10.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Decompress10(ref byte source, ref short destination)
	{
		Vector512<short> windows = Vector512.Create(0, 1, 2, 3, 4, 5, 6, 7, 5, 6, 7, 8, 9, 10, 11, 12, 10, 11, 12, 13, 14, 15, 16, 17, 15, 16, 17, 18, 19, 20, 21, 22);
		Vector512<byte> fields = Vector512.Create((byte)0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 6, 7, 7, 8, 8, 9, 0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 6, 7, 7, 8, 8, 9, 0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 6, 7, 7, 8, 8, 9, 0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 6, 7, 7, 8, 8, 9);
		Vector512<ushort> shifts = Vector512.Create((ushort)64, 16, 4, 1, 64, 16, 4, 1, 64, 16, 4, 1, 64, 16, 4, 1, 64, 16, 4, 1, 64, 16, 4, 1, 64, 16, 4, 1, 64, 16, 4, 1);

		for (int i = 0; i < 8; ++i)
		{
			Vector512<ushort> shifted = Avx512BW.Shuffle(Windows(ref source, 40 * i, 320, windows), fields).AsUInt16() * shifts >>> 4 & Vector512.Create((ushort)0x0FFC);
			DecompressValues(shifted.AsInt16()).StoreUnsafe(ref destination, (nuint)(32 * i));
		}
	}

	// Forty-four bytes per vector, eleven per 128-bit lane, then as in MLKemAvx2.Decompress11.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Decompress11(ref byte source, ref short destination)
	{
		Vector512<short> windows = Vector512.Create(0, 1, 2, 3, 4, 5, 6, 7, 5, 6, 7, 8, 9, 10, 11, 12, 11, 12, 13, 14, 15, 16, 17, 18, 16, 17, 18, 19, 20, 21, 22, 23);
		Vector512<byte> firstFields = Vector512.Create(0x80, 0, 1, 0x80, 0, 1, 2, 0x80, 1, 2, 3, 4, 3, 4, 5, 0x80, 0x80, 1, 2, 0x80, 1, 2, 3, 0x80, 2, 3, 4, 5, 4, 5, 6, 0x80, 0x80, 0, 1, 0x80, 0, 1, 2, 0x80, 1, 2, 3, 4, 3, 4, 5, 0x80, 0x80, 1, 2, 0x80, 1, 2, 3, 0x80, 2, 3, 4, 5, 4, 5, 6, 0x80);
		Vector512<byte> secondFields = Vector512.Create(4, 5, 6, 0x80, 5, 6, 7, 8, 7, 8, 9, 0x80, 8, 9, 10, 0x80, 5, 6, 7, 0x80, 6, 7, 8, 9, 8, 9, 10, 0x80, 9, 10, 11, 0x80, 4, 5, 6, 0x80, 5, 6, 7, 8, 7, 8, 9, 0x80, 8, 9, 10, 0x80, 5, 6, 7, 0x80, 6, 7, 8, 9, 8, 9, 10, 0x80, 9, 10, 11, 0x80);
		Vector512<uint> firstShifts = Vector512.Create(7u, 10, 13, 8, 7, 10, 13, 8, 7, 10, 13, 8, 7, 10, 13, 8);
		Vector512<uint> secondShifts = Vector512.Create(11u, 14, 9, 12, 11, 14, 9, 12, 11, 14, 9, 12, 11, 14, 9, 12);
		Vector512<uint> mask = Vector512.Create(0x0FFEu);

		for (int i = 0; i < 8; ++i)
		{
			Vector512<byte> window = Windows(ref source, 44 * i, 352, windows);
			Vector512<uint> first = Avx512F.ShiftRightLogicalVariable(Avx512BW.Shuffle(window, firstFields).AsUInt32(), firstShifts) & mask;
			Vector512<uint> second = Avx512F.ShiftRightLogicalVariable(Avx512BW.Shuffle(window, secondFields).AsUInt32(), secondShifts) & mask;
			DecompressValues(Avx512BW.PackUnsignedSaturate(first.AsInt32(), second.AsInt32()).AsInt16()).StoreUnsafe(ref destination, (nuint)(32 * i));
		}
	}

	// MLKemAvx2.SampleCbd2 on 64 bytes at a time.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void SampleCbd2(ref byte source, ref short destination)
	{
		for (nint i = 0; i < 2; ++i)
		{
			Vector512<byte> bits = Vector512.LoadUnsafe(ref source, (nuint)(64 * i));
			Vector512<byte> counts = (bits & Vector512.Create((byte)0x55)) + ((bits.AsUInt16() >>> 1).AsByte() & Vector512.Create((byte)0x55));
			Vector512<byte> differences = (counts & Vector512.Create((byte)0x33)) + Vector512.Create((byte)0x22) - ((counts.AsUInt16() >>> 2).AsByte() & Vector512.Create((byte)0x33));
			ref short block = ref Unsafe.Add(ref destination, 128 * i);
			SampleCbd2Spread(differences.GetLower().GetLower()).StoreUnsafe(ref block);
			SampleCbd2Spread(differences.GetLower().GetUpper()).StoreUnsafe(ref block, 32);
			SampleCbd2Spread(differences.GetUpper().GetLower()).StoreUnsafe(ref block, 64);
			SampleCbd2Spread(differences.GetUpper().GetUpper()).StoreUnsafe(ref block, 96);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<short> SampleCbd2Spread(Vector128<byte> differences)
	{
		Vector512<uint> widened = Avx512F.ConvertToVector512UInt32(differences);
		return ((widened | widened << 12) & Vector512.Create(0x000F000Fu)).AsInt16() - Vector512.Create((short)2);
	}

	// MLKemAvx2.SampleCbd3 with 48 bytes per 64 coefficients, each 128-bit lane taking twelve as in Decode12.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void SampleCbd3(ref byte source, ref short destination)
	{
		Vector512<byte> groups = Vector512.Create(0, 1, 2, 0x80, 3, 4, 5, 0x80, 6, 7, 8, 0x80, 9, 10, 11, 0x80, 0, 1, 2, 0x80, 3, 4, 5, 0x80, 6, 7, 8, 0x80, 9, 10, 11, 0x80, 0, 1, 2, 0x80, 3, 4, 5, 0x80, 6, 7, 8, 0x80, 9, 10, 11, 0x80, 0, 1, 2, 0x80, 3, 4, 5, 0x80, 6, 7, 8, 0x80, 9, 10, 11, 0x80);
		Vector512<byte> fields = Vector512.Create((byte)0, 1, 0, 1, 1, 2, 2, 3, 4, 5, 4, 5, 5, 6, 6, 7, 8, 9, 8, 9, 9, 10, 10, 11, 12, 13, 12, 13, 13, 14, 14, 15, 0, 1, 0, 1, 1, 2, 2, 3, 4, 5, 4, 5, 5, 6, 6, 7, 8, 9, 8, 9, 9, 10, 10, 11, 12, 13, 12, 13, 13, 14, 14, 15);
		Vector512<ushort> shifts = Vector512.Create((ushort)8192, 128, 512, 2048, 8192, 128, 512, 2048, 8192, 128, 512, 2048, 8192, 128, 512, 2048, 8192, 128, 512, 2048, 8192, 128, 512, 2048, 8192, 128, 512, 2048, 8192, 128, 512, 2048);
		Vector512<uint> ones = Vector512.Create(0x249249u);
		Vector512<uint> fieldMask = Vector512.Create(0x1C71C7u);

		for (int i = 0; i < 4; ++i)
		{
			Vector512<uint> bits = Avx512BW.Shuffle(Groups(ref source, 48 * i, 192).AsByte(), groups).AsUInt32();
			Vector512<uint> counts = (bits & ones) + (bits >>> 1 & ones) + (bits >>> 2 & ones);
			Vector512<ulong> differences = ((counts & fieldMask) + Vector512.Create(0xC30C3u) - (counts >>> 3 & fieldMask)).AsUInt64();
			ref short block = ref Unsafe.Add(ref destination, 64 * i);
			SampleCbd3Spread(Avx512F.PermuteVar8x64(differences, Vector512.Create(0UL, 1, 0, 1, 2, 3, 2, 3)).AsByte(), fields, shifts).StoreUnsafe(ref block);
			SampleCbd3Spread(Avx512F.PermuteVar8x64(differences, Vector512.Create(4UL, 5, 4, 5, 6, 7, 6, 7)).AsByte(), fields, shifts).StoreUnsafe(ref block, 32);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<short> SampleCbd3Spread(Vector512<byte> differences, Vector512<byte> fields, Vector512<ushort> shifts)
	{
		Vector512<ushort> raised = Avx512BW.Shuffle(differences, fields).AsUInt16() * shifts;
		return (raised >>> 13).AsInt16() - Vector512.Create((short)3);
	}

	// The twelve bytes of each quarter of the 48 at start, one quarter per 128-bit lane. The load moves back near the end of length
	// bytes to stay within them.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<int> Groups(ref byte source, int start, [ConstantExpected] int length)
	{
		int offset = Math.Min(start, length - 64);
		Vector512<int> groups = Vector512.Create(0, 1, 2, 0, 3, 4, 5, 0, 6, 7, 8, 0, 9, 10, 11, 0) + Vector512.Create(start - offset >> 2);
		return Avx512F.PermuteVar16x32(Vector512.LoadUnsafe(ref source, (nuint)offset).AsInt32(), groups);
	}

	// Spelled out for all four lanes, as a 512-bit vector made from a 128-bit constant is rebuilt with two inserts on every iteration
	// of a loop instead of being loaded whole.
	private static Vector512<byte> Encode12Bytes
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => Vector512.Create(0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 0x80, 0x80, 0x80, 0x80, 0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 0x80, 0x80, 0x80, 0x80, 0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 0x80, 0x80, 0x80, 0x80, 0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 0x80, 0x80, 0x80, 0x80);
	}

	private static Vector512<byte> Decode12Fields
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => Vector512.Create((byte)0, 1, 1, 2, 3, 4, 4, 5, 6, 7, 7, 8, 9, 10, 10, 11, 0, 1, 1, 2, 3, 4, 4, 5, 6, 7, 7, 8, 9, 10, 10, 11, 0, 1, 1, 2, 3, 4, 4, 5, 6, 7, 7, 8, 9, 10, 10, 11, 0, 1, 1, 2, 3, 4, 4, 5, 6, 7, 7, 8, 9, 10, 10, 11);
	}
}
