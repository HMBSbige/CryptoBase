namespace CryptoBase.Signatures.MLDsa;

// Sixteen coefficients per 512-bit vector, with products as in MLDsaAvx2. IsSupported requires Vector512.IsHardwareAccelerated too, which the runtime reports false where it prefers 256-bit vectors.
internal readonly partial struct MLDsaAvx512 : IMLDsaKernel
{
	private const int N = MLDsaConstants.N;
	private const int Q = MLDsaConstants.Q;
	private const int D = MLDsaConstants.D;

	public static bool IsSupported => Avx512BW.IsSupported && Vector512.IsHardwareAccelerated;

	// Layer 1 runs on vectors 128 coefficients apart, layers 2 to 4 on the eight vectors of each half, layers 5 to 8 in NttPair. The bounds are those of MLDsaAvx2.Ntt.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void Ntt(Span<int> f)
	{
		Debug.Assert(f.Length is N);

		ref Vector512<int> coefficients = ref Unsafe.As<int, Vector512<int>>(ref MemoryMarshal.GetReference(f));
		ref Vector512<int> zetas = ref Unsafe.As<int, Vector512<int>>(ref MemoryMarshal.GetReference(NttZetas));

		for (nint i = 0; i < 8; ++i)
		{
			Butterfly(ref Unsafe.Add(ref coefficients, i), ref Unsafe.Add(ref coefficients, i + 8), 1);
		}

		for (nint half = 0; half < 2; ++half)
		{
			ref Vector512<int> block = ref Unsafe.Add(ref coefficients, 8 * half);
			ref Vector512<int> pairZetas = ref Unsafe.Add(ref zetas, 40 * half);
			Vector512<int> v0 = block;
			Vector512<int> v1 = Unsafe.Add(ref block, 1);
			Vector512<int> v2 = Unsafe.Add(ref block, 2);
			Vector512<int> v3 = Unsafe.Add(ref block, 3);
			Vector512<int> v4 = Unsafe.Add(ref block, 4);
			Vector512<int> v5 = Unsafe.Add(ref block, 5);
			Vector512<int> v6 = Unsafe.Add(ref block, 6);
			Vector512<int> v7 = Unsafe.Add(ref block, 7);

			Butterfly(ref v0, ref v4, 2 + half);
			Butterfly(ref v1, ref v5, 2 + half);
			Butterfly(ref v2, ref v6, 2 + half);
			Butterfly(ref v3, ref v7, 2 + half);

			Butterfly(ref v0, ref v2, 4 + 2 * half);
			Butterfly(ref v1, ref v3, 4 + 2 * half);
			Butterfly(ref v4, ref v6, 5 + 2 * half);
			Butterfly(ref v5, ref v7, 5 + 2 * half);

			Butterfly(ref v0, ref v1, 8 + 4 * half);
			Butterfly(ref v2, ref v3, 9 + 4 * half);
			Butterfly(ref v4, ref v5, 10 + 4 * half);
			Butterfly(ref v6, ref v7, 11 + 4 * half);

			NttPair(v0, v1, ref pairZetas, out block);
			NttPair(v2, v3, ref Unsafe.Add(ref pairZetas, 10), out Unsafe.Add(ref block, 2));
			NttPair(v4, v5, ref Unsafe.Add(ref pairZetas, 20), out Unsafe.Add(ref block, 4));
			NttPair(v6, v7, ref Unsafe.Add(ref pairZetas, 30), out Unsafe.Add(ref block, 6));
		}
	}

	// The mirror of Ntt, with the bounds of MLDsaAvx2.InverseNtt.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void InverseNtt(Span<int> f)
	{
		Debug.Assert(f.Length is N);

		ref Vector512<int> coefficients = ref Unsafe.As<int, Vector512<int>>(ref MemoryMarshal.GetReference(f));
		ref Vector512<int> zetas = ref Unsafe.As<int, Vector512<int>>(ref MemoryMarshal.GetReference(InverseNttZetas));

		for (nint half = 0; half < 2; ++half)
		{
			ref Vector512<int> block = ref Unsafe.Add(ref coefficients, 8 * half);
			ref Vector512<int> pairZetas = ref Unsafe.Add(ref zetas, 40 * half);
			InverseNttPair(ref block, ref pairZetas, out Vector512<int> v0, out Vector512<int> v1);
			InverseNttPair(ref Unsafe.Add(ref block, 2), ref Unsafe.Add(ref pairZetas, 10), out Vector512<int> v2, out Vector512<int> v3);
			InverseNttPair(ref Unsafe.Add(ref block, 4), ref Unsafe.Add(ref pairZetas, 20), out Vector512<int> v4, out Vector512<int> v5);
			InverseNttPair(ref Unsafe.Add(ref block, 6), ref Unsafe.Add(ref pairZetas, 30), out Vector512<int> v6, out Vector512<int> v7);

			InverseButterfly(ref v0, ref v1, 15 - 4 * half);
			InverseButterfly(ref v2, ref v3, 14 - 4 * half);
			InverseButterfly(ref v4, ref v5, 13 - 4 * half);
			InverseButterfly(ref v6, ref v7, 12 - 4 * half);

			InverseButterfly(ref v0, ref v2, 7 - 2 * half);
			InverseButterfly(ref v1, ref v3, 7 - 2 * half);
			InverseButterfly(ref v4, ref v6, 6 - 2 * half);
			InverseButterfly(ref v5, ref v7, 6 - 2 * half);

			InverseButterfly(ref v0, ref v4, 3 - half);
			InverseButterfly(ref v1, ref v5, 3 - half);
			InverseButterfly(ref v2, ref v6, 3 - half);
			InverseButterfly(ref v3, ref v7, 3 - half);

			block = v0;
			Unsafe.Add(ref block, 1) = v1;
			Unsafe.Add(ref block, 2) = v2;
			Unsafe.Add(ref block, 3) = v3;
			Unsafe.Add(ref block, 4) = v4;
			Unsafe.Add(ref block, 5) = v5;
			Unsafe.Add(ref block, 6) = v6;
			Unsafe.Add(ref block, 7) = v7;
		}

		for (nint i = 0; i < 8; ++i)
		{
			LastInverseButterfly(ref Unsafe.Add(ref coefficients, i), ref Unsafe.Add(ref coefficients, i + 8));
		}
	}

	// MLDsaAvx2.MultiplyAccumulate on 512-bit vectors.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void MultiplyAccumulate(ReadOnlySpan<int> a, ReadOnlySpan<int> b, Span<int> destination, int count)
	{
		Debug.Assert(count is >= 1 and <= 8);
		Debug.Assert(a.Length >= count * N && b.Length >= count * N && destination.Length is N);

		ref int x = ref MemoryMarshal.GetReference(a);
		ref int y = ref MemoryMarshal.GetReference(b);
		ref int z = ref MemoryMarshal.GetReference(destination);
		nuint end = (nuint)count * N;

		for (nuint i = 0; i < N; i += 32)
		{
			Vector512<int> u0 = Vector512.LoadUnsafe(ref x, i);
			Vector512<int> v0 = Vector512.LoadUnsafe(ref y, i);
			Vector512<int> u1 = Vector512.LoadUnsafe(ref x, i + 16);
			Vector512<int> v1 = Vector512.LoadUnsafe(ref y, i + 16);
			Vector512<long> even0 = Avx512F.Multiply(u0, v0);
			Vector512<long> odd0 = Avx512F.Multiply(Odd(u0), Odd(v0));
			Vector512<long> even1 = Avx512F.Multiply(u1, v1);
			Vector512<long> odd1 = Avx512F.Multiply(Odd(u1), Odd(v1));

			for (nuint j = i + N; j < end; j += N)
			{
				u0 = Vector512.LoadUnsafe(ref x, j);
				v0 = Vector512.LoadUnsafe(ref y, j);
				u1 = Vector512.LoadUnsafe(ref x, j + 16);
				v1 = Vector512.LoadUnsafe(ref y, j + 16);
				even0 += Avx512F.Multiply(u0, v0);
				odd0 += Avx512F.Multiply(Odd(u0), Odd(v0));
				even1 += Avx512F.Multiply(u1, v1);
				odd1 += Avx512F.Multiply(Odd(u1), Odd(v1));
			}

			MontgomeryReduce(even0, odd0).StoreUnsafe(ref z, i);
			MontgomeryReduce(even1, odd1).StoreUnsafe(ref z, i + 16);
		}
	}

	// These do too little arithmetic per access to pay for 512-bit accesses that straddle cache lines, and polynomials in arrays or on the stack are seldom 64-byte aligned, so they run on 256-bit vectors.
	public static void Reduce(Span<int> f)
	{
		MLDsaAvx2.Reduce(f);
	}

	public static void Add(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination)
	{
		MLDsaAvx2.Add(left, right, destination);
	}

	// As MLDsaAvx2.ExceedsBound.
	public static bool ExceedsBound(ReadOnlySpan<int> f, int bound)
	{
		Debug.Assert(f.Length is N && bound is > 0 and <= 2097409);

		ref int coefficients = ref MemoryMarshal.GetReference(f);
		Vector512<int> limit = Vector512.Create(bound - 1);
		Vector512<int> exceeded = Vector512<int>.Zero;

		for (nuint i = 0; i < N; i += 16)
		{
			exceeded |= limit - Vector512.Abs(Vector512.LoadUnsafe(ref coefficients, i));
		}

		return exceeded.ExtractMostSignificantBits() is not 0;
	}

	public static bool AddReduceExceedsBound(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination, int bound)
	{
		return MLDsaAvx2.AddReduceExceedsBound(left, right, destination, bound);
	}

	public static bool SubtractReduceExceedsBound(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination, int bound)
	{
		return MLDsaAvx2.SubtractReduceExceedsBound(left, right, destination, bound);
	}

	public static bool ReduceExceedsBound(Span<int> f, int bound)
	{
		return MLDsaAvx2.ReduceExceedsBound(f, bound);
	}

	public static void Power2Round(ReadOnlySpan<int> t, Span<int> high, Span<int> low)
	{
		Debug.Assert(t.Length is N && high.Length is N && low.Length is N);

		ref int x = ref MemoryMarshal.GetReference(t);
		ref int y = ref MemoryMarshal.GetReference(high);
		ref int z = ref MemoryMarshal.GetReference(low);

		for (nuint i = 0; i < N; i += 16)
		{
			Vector512<int> r = ToCanonical(Reduce(Vector512.LoadUnsafe(ref x, i)));
			Vector512<int> r1 = r + Vector512.Create((1 << D - 1) - 1) >> D;
			r1.StoreUnsafe(ref y, i);
			(r - (r1 << D)).StoreUnsafe(ref z, i);
		}
	}

	public static void Decompose(ReadOnlySpan<int> r, Span<int> high, Span<int> low, int gamma2)
	{
		Debug.Assert(gamma2 is MLDsaConstants.Gamma2Small or MLDsaConstants.Gamma2Large);
		Debug.Assert(r.Length is N && high.Length is N && low.Length is N);

		ref int x = ref MemoryMarshal.GetReference(r);
		ref int y = ref MemoryMarshal.GetReference(high);
		ref int z = ref MemoryMarshal.GetReference(low);

		for (nuint i = 0; i < N; i += 16)
		{
			Decompose(Vector512.LoadUnsafe(ref x, i), gamma2, out Vector512<int> r0).StoreUnsafe(ref y, i);
			r0.StoreUnsafe(ref z, i);
		}
	}

	// As MLDsaAvx2.MakeHint.
	public static int MakeHint(ReadOnlySpan<int> low, ReadOnlySpan<int> high, Span<int> hint, int gamma2)
	{
		Debug.Assert(low.Length is N && high.Length is N && hint.Length is N);

		ref int x = ref MemoryMarshal.GetReference(low);
		ref int y = ref MemoryMarshal.GetReference(high);
		ref int z = ref MemoryMarshal.GetReference(hint);
		Vector512<int> bound = Vector512.Create(gamma2);
		Vector512<int> count = Vector512<int>.Zero;

		for (nuint i = 0; i < N; i += 16)
		{
			Vector512<int> a0 = Vector512.LoadUnsafe(ref x, i);
			Vector512<int> a1 = Vector512.LoadUnsafe(ref y, i);
			Vector512<int> wrapped = Vector512.AndNot(Vector512.Equals(a0, -bound), Vector512.Equals(a1, Vector512<int>.Zero));
			Vector512<int> set = Vector512.GreaterThan(a0, bound) | Vector512.LessThan(a0, -bound) | wrapped;
			(-set).StoreUnsafe(ref z, i);
			count -= set;
		}

		return Vector512.Sum(count);
	}

	// As MLDsaAvx2.UseHint.
	public static void UseHint(ReadOnlySpan<int> r, ReadOnlySpan<int> hint, Span<int> destination, int gamma2)
	{
		Debug.Assert(gamma2 is MLDsaConstants.Gamma2Small or MLDsaConstants.Gamma2Large);
		Debug.Assert(r.Length is N && hint.Length is N && destination.Length is N);

		ref int x = ref MemoryMarshal.GetReference(r);
		ref int y = ref MemoryMarshal.GetReference(hint);
		ref int z = ref MemoryMarshal.GetReference(destination);
		Vector512<int> m = Vector512.Create((Q - 1) / (2 * gamma2));

		for (nuint i = 0; i < N; i += 16)
		{
			Vector512<int> r1 = Decompose(Vector512.LoadUnsafe(ref x, i), gamma2, out Vector512<int> r0);
			Vector512<int> h = Vector512.LoadUnsafe(ref y, i);
			r1 += Vector512.ConditionalSelect(Vector512.GreaterThan(r0, Vector512<int>.Zero), h, -h);
			r1 += r1 >> 31 & m;
			r1 &= r1 - m >> 31;
			r1.StoreUnsafe(ref z, i);
		}
	}

	// Sixteen candidates from 48 bytes, each 128-bit lane taking 12; vpcompressd moves the accepted ones to the front, and a masked store writes no more of them than destination holds.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static unsafe int RejectSample(ReadOnlySpan<byte> source, Span<int> destination)
	{
		Debug.Assert(source.Length % 3 is 0);

		const int GroupLength = 48;
		Vector512<int> groups = Vector512.Create(0, 1, 2, 0, 3, 4, 5, 0, 6, 7, 8, 0, 9, 10, 11, 0);
		Vector512<byte> fields = Vector512.Create(Vector128.Create(0, 1, 2, 0x80, 3, 4, 5, 0x80, 6, 7, 8, 0x80, 9, 10, 11, 0x80));
		int count = 0;
		int offset = 0;

		fixed (byte* input = source)
		fixed (int* output = destination)
		{
			for (; offset <= source.Length - GroupLength && count < destination.Length; offset += GroupLength)
			{
				Vector512<byte> bytes = offset <= source.Length - Vector512<byte>.Count
					? Vector512.Load(input + offset)
					: Avx512BW.MaskLoad(input + offset, Vector512.LessThan(Vector512<byte>.Indices, Vector512.Create((byte)GroupLength)), Vector512<byte>.Zero);
				Vector512<byte> lanes = Avx512F.PermuteVar16x32(bytes.AsInt32(), groups).AsByte();
				Vector512<int> candidates = Avx512BW.Shuffle(lanes, fields).AsInt32() & Vector512.Create(0x7FFFFF);
				Vector512<int> accepted = Vector512.LessThan(candidates, Vector512.Create(Q));
				int written = Math.Min(BitOperations.PopCount(accepted.ExtractMostSignificantBits()), destination.Length - count);
				Store(Avx512F.Compress(Vector512<int>.Zero, accepted, candidates), output + count, written);
				count += written;
			}
		}

		if (count < destination.Length)
		{
			count += MLDsaScalar.RejectSample(source.Slice(offset), destination.Slice(count));
		}

		return count;
	}

	// Sixteen candidates from each 8 bytes, the low half of a byte first. vpcompressd moves the accepted ones to the front, and a masked store writes no more of them than destination holds; which they are says nothing of the values, as MLDsaAvx2.RejectEta argues.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static unsafe int RejectEta(ReadOnlySpan<byte> source, Span<int> destination, int eta)
	{
		Debug.Assert(eta is 2 or 4);

		Vector512<int> bound = Vector512.Create(eta is 2 ? 15 : 9);
		int count = 0;
		int offset = 0;

		fixed (byte* input = source)
		fixed (int* output = destination)
		{
			for (; offset <= source.Length - sizeof(ulong) && count < destination.Length; offset += sizeof(ulong))
			{
				Vector128<byte> bytes = Vector128.CreateScalar(Unsafe.ReadUnaligned<ulong>(input + offset)).AsByte();
				Vector512<int> b = Avx512F.ConvertToVector512Int32(Sse2.UnpackLow(bytes & Vector128.Create((byte)0x0F), bytes >>> 4));
				Vector512<int> accepted = Vector512.LessThan(b, bound);
				Vector512<int> values = eta is 2 ? (b * Vector512.Create(205) >>> 10) * Vector512.Create(5) - b + Vector512.Create(2) : ~b + Vector512.Create(5);
				int written = Math.Min(BitOperations.PopCount(accepted.ExtractMostSignificantBits()), destination.Length - count);
				Store(Avx512F.Compress(Vector512<int>.Zero, accepted, values), output + count, written);
				count += written;
			}
		}

		if (count < destination.Length)
		{
			count += MLDsaScalar.RejectEta(source.Slice(offset), destination.Slice(count), eta);
		}

		return count;
	}

	// The encoders and decoders run on 256-bit vectors: the bytes of a group of values come from or go to one 128-bit lane, which 512-bit vectors would only add lanes to.
	public static void EncodeT1(ReadOnlySpan<int> t1, Span<byte> destination)
	{
		MLDsaAvx2.EncodeT1(t1, destination);
	}

	public static void DecodeT1(ReadOnlySpan<byte> source, Span<int> f)
	{
		MLDsaAvx2.DecodeT1(source, f);
	}

	public static void EncodeT0(ReadOnlySpan<int> t0, Span<byte> destination)
	{
		MLDsaAvx2.EncodeT0(t0, destination);
	}

	public static void EncodeEta(ReadOnlySpan<int> s, Span<byte> destination, int eta)
	{
		MLDsaAvx2.EncodeEta(s, destination, eta);
	}

	public static bool DecodeEta(ReadOnlySpan<byte> source, Span<int> s, int eta)
	{
		return MLDsaAvx2.DecodeEta(source, s, eta);
	}

	public static void EncodeZ(ReadOnlySpan<int> z, Span<byte> destination, int gamma1Bits)
	{
		MLDsaAvx2.EncodeZ(z, destination, gamma1Bits);
	}

	public static void DecodeZ(ReadOnlySpan<byte> source, Span<int> z, int gamma1Bits)
	{
		MLDsaAvx2.DecodeZ(source, z, gamma1Bits);
	}

	public static void EncodeW1(ReadOnlySpan<int> w1, Span<byte> destination, int gamma2)
	{
		MLDsaAvx2.EncodeW1(w1, destination, gamma2);
	}

	// Layers 5 to 8 of NTT on the 32 coefficients of a and b, written back in order to destination.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void NttPair(Vector512<int> a, Vector512<int> b, ref Vector512<int> zetas, out Vector512<int> destination)
	{
		Vector512<int> low = Avx512F.Shuffle4x128(a, b, 0b01_00_01_00);
		Vector512<int> high = Avx512F.Shuffle4x128(a, b, 0b11_10_11_10);
		Butterfly(ref low, ref high, zetas, Unsafe.Add(ref zetas, 1));

		a = Avx512F.Shuffle4x128(low, high, 0b10_00_10_00);
		b = Avx512F.Shuffle4x128(low, high, 0b11_01_11_01);
		Butterfly(ref a, ref b, Unsafe.Add(ref zetas, 2), Unsafe.Add(ref zetas, 3));

		low = Avx512F.UnpackLow(a.AsInt64(), b.AsInt64()).AsInt32();
		high = Avx512F.UnpackHigh(a.AsInt64(), b.AsInt64()).AsInt32();
		Butterfly(ref low, ref high, Unsafe.Add(ref zetas, 4), Unsafe.Add(ref zetas, 5));

		a = Avx512F.Shuffle(low.AsSingle(), high.AsSingle(), 0b10_00_10_00).AsInt32();
		b = Avx512F.Shuffle(low.AsSingle(), high.AsSingle(), 0b11_01_11_01).AsInt32();
		Butterfly(ref a, ref b, ref Unsafe.Add(ref zetas, 6));

		destination = Avx512F.PermuteVar16x32x2(a, Vector512.Create(0, 16, 2, 18, 1, 17, 3, 19, 8, 24, 10, 26, 9, 25, 11, 27), b);
		Unsafe.Add(ref destination, 1) = Avx512F.PermuteVar16x32x2(a, Vector512.Create(4, 20, 6, 22, 5, 21, 7, 23, 12, 28, 14, 30, 13, 29, 15, 31), b);
	}

	// Layers 1 to 4 of NTT⁻¹ on the 32 coefficients at source, undoing the moves of NttPair.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseNttPair(ref Vector512<int> source, ref Vector512<int> zetas, out Vector512<int> first, out Vector512<int> second)
	{
		Vector512<int> x = source;
		Vector512<int> y = Unsafe.Add(ref source, 1);
		Vector512<int> a = Avx512F.PermuteVar16x32x2(x, Vector512.Create(0, 4, 2, 6, 16, 20, 18, 22, 8, 12, 10, 14, 24, 28, 26, 30), y);
		Vector512<int> b = Avx512F.PermuteVar16x32x2(x, Vector512.Create(1, 5, 3, 7, 17, 21, 19, 23, 9, 13, 11, 15, 25, 29, 27, 31), y);
		InverseButterfly(ref a, ref b, ref zetas);

		Vector512<int> low = Avx512F.UnpackLow(a, b);
		Vector512<int> high = Avx512F.UnpackHigh(a, b);
		InverseButterfly(ref low, ref high, Unsafe.Add(ref zetas, 4), Unsafe.Add(ref zetas, 5));

		a = Avx512F.UnpackLow(low.AsInt64(), high.AsInt64()).AsInt32();
		b = Avx512F.UnpackHigh(low.AsInt64(), high.AsInt64()).AsInt32();
		InverseButterfly(ref a, ref b, Unsafe.Add(ref zetas, 6), Unsafe.Add(ref zetas, 7));

		low = Avx512F.PermuteVar8x64x2(a.AsInt64(), Vector512.Create(0L, 1, 8, 9, 2, 3, 10, 11), b.AsInt64()).AsInt32();
		high = Avx512F.PermuteVar8x64x2(a.AsInt64(), Vector512.Create(4L, 5, 12, 13, 6, 7, 14, 15), b.AsInt64()).AsInt32();
		InverseButterfly(ref low, ref high, Unsafe.Add(ref zetas, 8), Unsafe.Add(ref zetas, 9));

		first = Avx512F.Shuffle4x128(low, high, 0b01_00_01_00);
		second = Avx512F.Shuffle4x128(low, high, 0b11_10_11_10);
	}

	// The butterfly of NTT (Algorithm 41) with Zetas[index] in every lane.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Butterfly(ref Vector512<int> low, ref Vector512<int> high, nint index)
	{
		Vector512<int> zeta = Vector512.Create(Unsafe.Add(ref MemoryMarshal.GetReference(MLDsaConstants.Zetas), index));
		Vector512<int> zetaQInverse = Vector512.Create(Unsafe.Add(ref MemoryMarshal.GetReference(MLDsaConstants.ZetasQInverse), index));
		Butterfly(ref low, ref high, zeta, zetaQInverse);
	}

	// With the same zeta in each pair of lanes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Butterfly(ref Vector512<int> low, ref Vector512<int> high, Vector512<int> zeta, Vector512<int> zetaQInverse)
	{
		Vector512<int> t = MultiplyMontgomery(high, zeta, zetaQInverse, zeta, zetaQInverse);
		high = low - t;
		low += t;
	}

	// With the four vectors of zetas at zetas, as in MLDsaAvx2.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Butterfly(ref Vector512<int> low, ref Vector512<int> high, ref Vector512<int> zetas)
	{
		Vector512<int> t = MultiplyMontgomery(high, zetas, Unsafe.Add(ref zetas, 1), Unsafe.Add(ref zetas, 2), Unsafe.Add(ref zetas, 3));
		high = low - t;
		low += t;
	}

	// The butterfly of NTT⁻¹ (Algorithm 42), its (low − high) · (−Zetas[index]) taken as (high − low) · Zetas[index].
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseButterfly(ref Vector512<int> low, ref Vector512<int> high, nint index)
	{
		Vector512<int> zeta = Vector512.Create(Unsafe.Add(ref MemoryMarshal.GetReference(MLDsaConstants.Zetas), index));
		Vector512<int> zetaQInverse = Vector512.Create(Unsafe.Add(ref MemoryMarshal.GetReference(MLDsaConstants.ZetasQInverse), index));
		InverseButterfly(ref low, ref high, zeta, zetaQInverse);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseButterfly(ref Vector512<int> low, ref Vector512<int> high, Vector512<int> zeta, Vector512<int> zetaQInverse)
	{
		Vector512<int> difference = high - low;
		low += high;
		high = MultiplyMontgomery(difference, zeta, zetaQInverse, zeta, zetaQInverse);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseButterfly(ref Vector512<int> low, ref Vector512<int> high, ref Vector512<int> zetas)
	{
		Vector512<int> difference = high - low;
		low += high;
		high = MultiplyMontgomery(difference, zetas, Unsafe.Add(ref zetas, 1), Unsafe.Add(ref zetas, 2), Unsafe.Add(ref zetas, 3));
	}

	// Layer 8 of NTT⁻¹ with the factor that ends it.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LastInverseButterfly(ref Vector512<int> low, ref Vector512<int> high)
	{
		Vector512<int> factor = Vector512.Create(MLDsaConstants.InverseNttFactor);
		Vector512<int> factorQInverse = Vector512.Create(MLDsaConstants.InverseNttFactorQInverse);
		Vector512<int> zeta = Vector512.Create(MLDsaConstants.LastInverseZeta);
		Vector512<int> zetaQInverse = Vector512.Create(MLDsaConstants.LastInverseZetaQInverse);
		Vector512<int> difference = high - low;
		low = MultiplyMontgomery(low + high, factor, factorQInverse, factor, factorQInverse);
		high = MultiplyMontgomery(difference, zeta, zetaQInverse, zeta, zetaQInverse);
	}

	// MLDsaAvx2.MultiplyMontgomery on 512-bit vectors.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<int> MultiplyMontgomery(Vector512<int> a, Vector512<int> zeta, Vector512<int> zetaQInverse, Vector512<int> zetaOdd, Vector512<int> zetaOddQInverse)
	{
		Vector512<int> q = Vector512.Create(Q);
		Vector512<int> aOdd = Odd(a);
		Vector512<long> even = Avx512F.Multiply(a, zeta) - Avx512F.Multiply(Avx512F.Multiply(a, zetaQInverse).AsInt32(), q);
		Vector512<long> odd = Avx512F.Multiply(aOdd, zetaOdd) - Avx512F.Multiply(Avx512F.Multiply(aOdd, zetaOddQInverse).AsInt32(), q);
		return (even.AsUInt64() >>> 32).AsInt32() | odd.AsInt32();
	}

	// MLDsaAvx2.MontgomeryReduce on 512-bit vectors.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<int> MontgomeryReduce(Vector512<long> even, Vector512<long> odd)
	{
		Vector512<int> q = Vector512.Create(Q);
		Vector512<int> qInverse = Vector512.Create(MLDsaConstants.QInverse);
		even -= Avx512F.Multiply(Avx512F.Multiply(even.AsInt32(), qInverse).AsInt32(), q);
		odd -= Avx512F.Multiply(Avx512F.Multiply(odd.AsInt32(), qInverse).AsInt32(), q);
		return (even.AsUInt64() >>> 32).AsInt32() | odd.AsInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<int> Odd(Vector512<int> a)
	{
		return (a.AsInt64() >>> 32).AsInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<int> Reduce(Vector512<int> a)
	{
		Vector512<int> quotient = a + Vector512.Create(1 << 22) >> 23;
		return a - quotient * Vector512.Create(Q);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<int> ToCanonical(Vector512<int> a)
	{
		return a + (a >> 31 & Vector512.Create(Q));
	}

	// MLDsaScalar.Decompose in every lane.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<int> Decompose(Vector512<int> r, int gamma2, out Vector512<int> r0)
	{
		Vector512<int> a = ToCanonical(r);
		Vector512<int> a1 = a + Vector512.Create(127) >> 7;

		if (gamma2 is MLDsaConstants.Gamma2Large)
		{
			a1 = a1 * Vector512.Create(1025) + Vector512.Create(1 << 21) >> 22 & Vector512.Create(15);
		}
		else
		{
			a1 = a1 * Vector512.Create(11275) + Vector512.Create(1 << 23) >> 24;
			a1 &= a1 - Vector512.Create(44) >> 31;
		}

		r0 = a - a1 * Vector512.Create(2 * gamma2);
		r0 -= Vector512.AndNot(Vector512.Create(Q), r0 - Vector512.Create((Q + 1) / 2) >> 31);
		return a1;
	}

	// The first count lanes of value at destination.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static unsafe void Store(Vector512<int> value, int* destination, int count)
	{
		Avx512F.MaskStore(destination, Vector512.LessThan(Vector512<int>.Indices, Vector512.Create(count)), value);
	}
}
