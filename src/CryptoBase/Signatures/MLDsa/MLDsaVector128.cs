using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Signatures.MLDsa;

// Four coefficients per 128-bit vector, one implementation for SSE4.1 and AdvSimd. A product with a zeta takes pmuldq for the even and
// for the odd lanes on SSE4.1 and sqdmulh on AdvSimd. Encoders and decoders never access past the end of a buffer.
internal readonly partial struct MLDsaVector128 : IMLDsaKernel
{
	private const int N = MLDsaConstants.N;
	private const int Q = MLDsaConstants.Q;
	private const int D = MLDsaConstants.D;

	private const byte Zero = 0xFF;

	public static bool IsSupported => Sse41.IsSupported || AdvSimd.Arm64.IsSupported;

	// Layers 1 to 3 run on eight vectors 32 coefficients apart, layers 4 to 6 on eight consecutive ones, of which NttPair shuffles
	// each pair for layers 7 and 8. A product by a zeta is below q, so eight layers keep the coefficients below 9q without reduction.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void Ntt(Span<int> f)
	{
		Debug.Assert(f.Length is N);

		ref int coefficients = ref MemoryMarshal.GetReference(f);
		ref int zetas = ref MemoryMarshal.GetReference(NttZetas);

		for (nuint offset = 0; offset < 32; offset += 4)
		{
			ref int p = ref Unsafe.Add(ref coefficients, offset);
			Vector128<int> f0 = Vector128.LoadUnsafe(ref p);
			Vector128<int> f1 = Vector128.LoadUnsafe(ref p, 32);
			Vector128<int> f2 = Vector128.LoadUnsafe(ref p, 64);
			Vector128<int> f3 = Vector128.LoadUnsafe(ref p, 96);
			Vector128<int> f4 = Vector128.LoadUnsafe(ref p, 128);
			Vector128<int> f5 = Vector128.LoadUnsafe(ref p, 160);
			Vector128<int> f6 = Vector128.LoadUnsafe(ref p, 192);
			Vector128<int> f7 = Vector128.LoadUnsafe(ref p, 224);

			Butterfly(ref f0, ref f4, 1);
			Butterfly(ref f1, ref f5, 1);
			Butterfly(ref f2, ref f6, 1);
			Butterfly(ref f3, ref f7, 1);

			Butterfly(ref f0, ref f2, 2);
			Butterfly(ref f1, ref f3, 2);
			Butterfly(ref f4, ref f6, 3);
			Butterfly(ref f5, ref f7, 3);

			Butterfly(ref f0, ref f1, 4);
			Butterfly(ref f2, ref f3, 5);
			Butterfly(ref f4, ref f5, 6);
			Butterfly(ref f6, ref f7, 7);

			f0.StoreUnsafe(ref p);
			f1.StoreUnsafe(ref p, 32);
			f2.StoreUnsafe(ref p, 64);
			f3.StoreUnsafe(ref p, 96);
			f4.StoreUnsafe(ref p, 128);
			f5.StoreUnsafe(ref p, 160);
			f6.StoreUnsafe(ref p, 192);
			f7.StoreUnsafe(ref p, 224);
		}

		for (nint block = 0; block < 8; ++block)
		{
			ref int p = ref Unsafe.Add(ref coefficients, 32 * block);
			ref int pairZetas = ref Unsafe.Add(ref zetas, 128 * block);
			Vector128<int> f0 = Vector128.LoadUnsafe(ref p);
			Vector128<int> f1 = Vector128.LoadUnsafe(ref p, 4);
			Vector128<int> f2 = Vector128.LoadUnsafe(ref p, 8);
			Vector128<int> f3 = Vector128.LoadUnsafe(ref p, 12);
			Vector128<int> f4 = Vector128.LoadUnsafe(ref p, 16);
			Vector128<int> f5 = Vector128.LoadUnsafe(ref p, 20);
			Vector128<int> f6 = Vector128.LoadUnsafe(ref p, 24);
			Vector128<int> f7 = Vector128.LoadUnsafe(ref p, 28);

			Butterfly(ref f0, ref f4, 8 + block);
			Butterfly(ref f1, ref f5, 8 + block);
			Butterfly(ref f2, ref f6, 8 + block);
			Butterfly(ref f3, ref f7, 8 + block);

			Butterfly(ref f0, ref f2, 16 + 2 * block);
			Butterfly(ref f1, ref f3, 16 + 2 * block);
			Butterfly(ref f4, ref f6, 17 + 2 * block);
			Butterfly(ref f5, ref f7, 17 + 2 * block);

			Butterfly(ref f0, ref f1, 32 + 4 * block);
			Butterfly(ref f2, ref f3, 33 + 4 * block);
			Butterfly(ref f4, ref f5, 34 + 4 * block);
			Butterfly(ref f6, ref f7, 35 + 4 * block);

			NttPair(ref f0, ref f1, ref pairZetas);
			NttPair(ref f2, ref f3, ref Unsafe.Add(ref pairZetas, 32));
			NttPair(ref f4, ref f5, ref Unsafe.Add(ref pairZetas, 64));
			NttPair(ref f6, ref f7, ref Unsafe.Add(ref pairZetas, 96));

			f0.StoreUnsafe(ref p);
			f1.StoreUnsafe(ref p, 4);
			f2.StoreUnsafe(ref p, 8);
			f3.StoreUnsafe(ref p, 12);
			f4.StoreUnsafe(ref p, 16);
			f5.StoreUnsafe(ref p, 20);
			f6.StoreUnsafe(ref p, 24);
			f7.StoreUnsafe(ref p, 28);
		}
	}

	// The layers of Ntt in reverse. The sums double in each layer, so they stay below 256q < 2^31 without reduction.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void InverseNtt(Span<int> f)
	{
		Debug.Assert(f.Length is N);

		ref int coefficients = ref MemoryMarshal.GetReference(f);
		ref int zetas = ref MemoryMarshal.GetReference(InverseNttZetas);

		for (nint block = 0; block < 8; ++block)
		{
			ref int p = ref Unsafe.Add(ref coefficients, 32 * block);
			ref int pairZetas = ref Unsafe.Add(ref zetas, 128 * block);
			Vector128<int> f0 = Vector128.LoadUnsafe(ref p);
			Vector128<int> f1 = Vector128.LoadUnsafe(ref p, 4);
			Vector128<int> f2 = Vector128.LoadUnsafe(ref p, 8);
			Vector128<int> f3 = Vector128.LoadUnsafe(ref p, 12);
			Vector128<int> f4 = Vector128.LoadUnsafe(ref p, 16);
			Vector128<int> f5 = Vector128.LoadUnsafe(ref p, 20);
			Vector128<int> f6 = Vector128.LoadUnsafe(ref p, 24);
			Vector128<int> f7 = Vector128.LoadUnsafe(ref p, 28);

			InverseNttPair(ref f0, ref f1, ref pairZetas);
			InverseNttPair(ref f2, ref f3, ref Unsafe.Add(ref pairZetas, 32));
			InverseNttPair(ref f4, ref f5, ref Unsafe.Add(ref pairZetas, 64));
			InverseNttPair(ref f6, ref f7, ref Unsafe.Add(ref pairZetas, 96));

			InverseButterfly(ref f0, ref f1, 63 - 4 * block);
			InverseButterfly(ref f2, ref f3, 62 - 4 * block);
			InverseButterfly(ref f4, ref f5, 61 - 4 * block);
			InverseButterfly(ref f6, ref f7, 60 - 4 * block);

			InverseButterfly(ref f0, ref f2, 31 - 2 * block);
			InverseButterfly(ref f1, ref f3, 31 - 2 * block);
			InverseButterfly(ref f4, ref f6, 30 - 2 * block);
			InverseButterfly(ref f5, ref f7, 30 - 2 * block);

			InverseButterfly(ref f0, ref f4, 15 - block);
			InverseButterfly(ref f1, ref f5, 15 - block);
			InverseButterfly(ref f2, ref f6, 15 - block);
			InverseButterfly(ref f3, ref f7, 15 - block);

			f0.StoreUnsafe(ref p);
			f1.StoreUnsafe(ref p, 4);
			f2.StoreUnsafe(ref p, 8);
			f3.StoreUnsafe(ref p, 12);
			f4.StoreUnsafe(ref p, 16);
			f5.StoreUnsafe(ref p, 20);
			f6.StoreUnsafe(ref p, 24);
			f7.StoreUnsafe(ref p, 28);
		}

		for (nuint offset = 0; offset < 32; offset += 4)
		{
			ref int p = ref Unsafe.Add(ref coefficients, offset);
			Vector128<int> f0 = Vector128.LoadUnsafe(ref p);
			Vector128<int> f1 = Vector128.LoadUnsafe(ref p, 32);
			Vector128<int> f2 = Vector128.LoadUnsafe(ref p, 64);
			Vector128<int> f3 = Vector128.LoadUnsafe(ref p, 96);
			Vector128<int> f4 = Vector128.LoadUnsafe(ref p, 128);
			Vector128<int> f5 = Vector128.LoadUnsafe(ref p, 160);
			Vector128<int> f6 = Vector128.LoadUnsafe(ref p, 192);
			Vector128<int> f7 = Vector128.LoadUnsafe(ref p, 224);

			InverseButterfly(ref f0, ref f1, 7);
			InverseButterfly(ref f2, ref f3, 6);
			InverseButterfly(ref f4, ref f5, 5);
			InverseButterfly(ref f6, ref f7, 4);

			InverseButterfly(ref f0, ref f2, 3);
			InverseButterfly(ref f1, ref f3, 3);
			InverseButterfly(ref f4, ref f6, 2);
			InverseButterfly(ref f5, ref f7, 2);

			LastInverseButterfly(ref f0, ref f4);
			LastInverseButterfly(ref f1, ref f5);
			LastInverseButterfly(ref f2, ref f6);
			LastInverseButterfly(ref f3, ref f7);

			f0.StoreUnsafe(ref p);
			f1.StoreUnsafe(ref p, 32);
			f2.StoreUnsafe(ref p, 64);
			f3.StoreUnsafe(ref p, 96);
			f4.StoreUnsafe(ref p, 128);
			f5.StoreUnsafe(ref p, 160);
			f6.StoreUnsafe(ref p, 192);
			f7.StoreUnsafe(ref p, 224);
		}
	}

	// The products sum in 64 bits, the even and the odd lanes apart on SSE4.1, and lanes 0 and 1 apart from lanes 2 and 3 on AdvSimd.
	// A product is below 9q², so the sum of eight stays below 2^31 · q, the input bound of MontgomeryReduce.
	// Each pass takes two vectors through all the polynomials, and the products of the first polynomial start the sums.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void MultiplyAccumulate(ReadOnlySpan<int> a, ReadOnlySpan<int> b, Span<int> destination, int count)
	{
		Debug.Assert(count is >= 1 and <= 8);
		Debug.Assert(a.Length >= count * N && b.Length >= count * N && destination.Length is N);

		ref int x = ref MemoryMarshal.GetReference(a);
		ref int y = ref MemoryMarshal.GetReference(b);
		ref int z = ref MemoryMarshal.GetReference(destination);
		nuint end = (nuint)count * N;

		for (nuint i = 0; i < N; i += 8)
		{
			Vector128<long> first0 = Multiply(Vector128.LoadUnsafe(ref x, i), Vector128.LoadUnsafe(ref y, i), out Vector128<long> second0);
			Vector128<long> first1 = Multiply(Vector128.LoadUnsafe(ref x, i + 4), Vector128.LoadUnsafe(ref y, i + 4), out Vector128<long> second1);

			for (nuint j = i + N; j < end; j += N)
			{
				MultiplyAdd(ref first0, ref second0, Vector128.LoadUnsafe(ref x, j), Vector128.LoadUnsafe(ref y, j));
				MultiplyAdd(ref first1, ref second1, Vector128.LoadUnsafe(ref x, j + 4), Vector128.LoadUnsafe(ref y, j + 4));
			}

			MontgomeryReduce(first0, second0).StoreUnsafe(ref z, i);
			MontgomeryReduce(first1, second1).StoreUnsafe(ref z, i + 4);
		}
	}

	public static void Reduce(Span<int> f)
	{
		Debug.Assert(f.Length is N);

		ref int coefficients = ref MemoryMarshal.GetReference(f);

		for (nuint i = 0; i < N; i += 4)
		{
			Reduce(Vector128.LoadUnsafe(ref coefficients, i)).StoreUnsafe(ref coefficients, i);
		}
	}

	public static void Add(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination)
	{
		Debug.Assert(left.Length is N && right.Length is N && destination.Length is N);

		ref int x = ref MemoryMarshal.GetReference(left);
		ref int y = ref MemoryMarshal.GetReference(right);
		ref int z = ref MemoryMarshal.GetReference(destination);

		for (nuint i = 0; i < N; i += 4)
		{
			(Vector128.LoadUnsafe(ref x, i) + Vector128.LoadUnsafe(ref y, i)).StoreUnsafe(ref z, i);
		}
	}

	// As in MLDsaScalar.ExceedsBound, bound − 1 − |f_i| is negative exactly where the bound is reached; the signs gather with or.
	public static bool ExceedsBound(ReadOnlySpan<int> f, int bound)
	{
		Debug.Assert(f.Length is N && bound is > 0 and <= 2097409);

		ref int coefficients = ref MemoryMarshal.GetReference(f);
		Vector128<int> limit = Vector128.Create(bound - 1);
		Vector128<int> exceeded = Vector128<int>.Zero;

		for (nuint i = 0; i < N; i += 4)
		{
			exceeded |= limit - Vector128.Abs(Vector128.LoadUnsafe(ref coefficients, i));
		}

		return Vector128.LessThanAny(exceeded, Vector128<int>.Zero);
	}

	public static bool AddReduceExceedsBound(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination, int bound)
	{
		Debug.Assert(left.Length is N && right.Length is N && destination.Length is N && bound is > 0 and <= 2097409);

		ref int x = ref MemoryMarshal.GetReference(left);
		ref int y = ref MemoryMarshal.GetReference(right);
		ref int z = ref MemoryMarshal.GetReference(destination);
		Vector128<int> limit = Vector128.Create(bound - 1);
		Vector128<int> exceeded = Vector128<int>.Zero;

		for (nuint i = 0; i < N; i += 4)
		{
			Vector128<int> value = Reduce(Vector128.LoadUnsafe(ref x, i) + Vector128.LoadUnsafe(ref y, i));
			value.StoreUnsafe(ref z, i);
			exceeded |= limit - Vector128.Abs(value);
		}

		return Vector128.LessThanAny(exceeded, Vector128<int>.Zero);
	}

	public static bool SubtractReduceExceedsBound(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination, int bound)
	{
		Debug.Assert(left.Length is N && right.Length is N && destination.Length is N && bound is > 0 and <= 2097409);

		ref int x = ref MemoryMarshal.GetReference(left);
		ref int y = ref MemoryMarshal.GetReference(right);
		ref int z = ref MemoryMarshal.GetReference(destination);
		Vector128<int> limit = Vector128.Create(bound - 1);
		Vector128<int> exceeded = Vector128<int>.Zero;

		for (nuint i = 0; i < N; i += 4)
		{
			Vector128<int> value = Reduce(Vector128.LoadUnsafe(ref x, i) - Vector128.LoadUnsafe(ref y, i));
			value.StoreUnsafe(ref z, i);
			exceeded |= limit - Vector128.Abs(value);
		}

		return Vector128.LessThanAny(exceeded, Vector128<int>.Zero);
	}

	public static bool ReduceExceedsBound(Span<int> f, int bound)
	{
		Debug.Assert(f.Length is N && bound is > 0 and <= 2097409);

		ref int coefficients = ref MemoryMarshal.GetReference(f);
		Vector128<int> limit = Vector128.Create(bound - 1);
		Vector128<int> exceeded = Vector128<int>.Zero;

		for (nuint i = 0; i < N; i += 4)
		{
			Vector128<int> value = Reduce(Vector128.LoadUnsafe(ref coefficients, i));
			value.StoreUnsafe(ref coefficients, i);
			exceeded |= limit - Vector128.Abs(value);
		}

		return Vector128.LessThanAny(exceeded, Vector128<int>.Zero);
	}

	public static void Power2Round(ReadOnlySpan<int> t, Span<int> high, Span<int> low)
	{
		Debug.Assert(t.Length is N && high.Length is N && low.Length is N);

		ref int x = ref MemoryMarshal.GetReference(t);
		ref int y = ref MemoryMarshal.GetReference(high);
		ref int z = ref MemoryMarshal.GetReference(low);

		for (nuint i = 0; i < N; i += 4)
		{
			Vector128<int> r = ToCanonical(Reduce(Vector128.LoadUnsafe(ref x, i)));
			Vector128<int> r1 = r + Vector128.Create((1 << D - 1) - 1) >> D;
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

		for (nuint i = 0; i < N; i += 4)
		{
			Decompose(Vector128.LoadUnsafe(ref x, i), gamma2, out Vector128<int> r0).StoreUnsafe(ref y, i);
			r0.StoreUnsafe(ref z, i);
		}
	}

	// The hint of MLDsaScalar.MakeHint in every lane; the masks of the hints count down from zero.
	public static int MakeHint(ReadOnlySpan<int> low, ReadOnlySpan<int> high, Span<int> hint, int gamma2)
	{
		Debug.Assert(low.Length is N && high.Length is N && hint.Length is N);

		ref int x = ref MemoryMarshal.GetReference(low);
		ref int y = ref MemoryMarshal.GetReference(high);
		ref int z = ref MemoryMarshal.GetReference(hint);
		Vector128<int> bound = Vector128.Create(gamma2);
		Vector128<int> count = Vector128<int>.Zero;

		for (nuint i = 0; i < N; i += 4)
		{
			Vector128<int> a0 = Vector128.LoadUnsafe(ref x, i);
			Vector128<int> a1 = Vector128.LoadUnsafe(ref y, i);
			Vector128<int> wrapped = Vector128.AndNot(Vector128.Equals(a0, -bound), Vector128.Equals(a1, Vector128<int>.Zero));
			Vector128<int> set = Vector128.GreaterThan(a0, bound) | Vector128.LessThan(a0, -bound) | wrapped;
			(-set).StoreUnsafe(ref z, i);
			count -= set;
		}

		return Vector128.Sum(count);
	}

	// As in MLDsaScalar.UseHint, with the step of the hint chosen by mask and wrapped modulo m in both directions.
	public static void UseHint(ReadOnlySpan<int> r, ReadOnlySpan<int> hint, Span<int> destination, int gamma2)
	{
		Debug.Assert(gamma2 is MLDsaConstants.Gamma2Small or MLDsaConstants.Gamma2Large);
		Debug.Assert(r.Length is N && hint.Length is N && destination.Length is N);

		ref int x = ref MemoryMarshal.GetReference(r);
		ref int y = ref MemoryMarshal.GetReference(hint);
		ref int z = ref MemoryMarshal.GetReference(destination);
		Vector128<int> m = Vector128.Create((Q - 1) / (2 * gamma2));

		for (nuint i = 0; i < N; i += 4)
		{
			Vector128<int> r1 = Decompose(Vector128.LoadUnsafe(ref x, i), gamma2, out Vector128<int> r0);
			Vector128<int> h = Vector128.LoadUnsafe(ref y, i);
			r1 += Vector128.ConditionalSelect(Vector128.GreaterThan(r0, Vector128<int>.Zero), h, -h);
			r1 += r1 >> 31 & m;
			r1 -= Vector128.GreaterThanOrEqual(r1, m) & m;
			r1.StoreUnsafe(ref z, i);
		}
	}

	// Four candidates from 12 bytes; a shuffle moves the accepted ones to the front of a buffer that takes whole vectors. The bytes
	// are public, so the shuffle may depend on them.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static int RejectSample(ReadOnlySpan<byte> source, Span<int> destination)
	{
		Debug.Assert(source.Length % 3 is 0);

		const int GroupLength = 12;
		Span<int> buffer = stackalloc int[N + 4];
		ref byte input = ref MemoryMarshal.GetReference(source);
		ref int output = ref MemoryMarshal.GetReference(buffer);
		ref byte shuffles = ref MemoryMarshal.GetReference(RejectShuffles);
		Vector128<byte> fields = Vector128.Create(0, 1, 2, Zero, 3, 4, 5, Zero, 6, 7, 8, Zero, 9, 10, 11, Zero);
		int limit = Math.Min(destination.Length, N);
		int count = 0;
		int offset = 0;

		for (; offset <= source.Length - Vector128<byte>.Count && count < limit; offset += GroupLength)
		{
			Vector128<int> candidates = Vector128.Shuffle(Vector128.LoadUnsafe(ref input, (nuint)offset), fields).AsInt32() & Vector128.Create(0x7FFFFF);
			uint accepted = ExtractMask(Vector128.LessThan(candidates, Vector128.Create(Q)));
			Vector128<byte> shuffle = Vector128.LoadUnsafe(ref shuffles, 16 * accepted);
			Vector128.ShuffleNative(candidates.AsByte(), shuffle).AsInt32().StoreUnsafe(ref output, (nuint)count);
			count += BitOperations.PopCount(accepted);
		}

		count = Math.Min(count, destination.Length);
		buffer.Slice(0, count).CopyTo(destination);

		if (count < destination.Length)
		{
			count += MLDsaScalar.RejectSample(source.Slice(offset), destination.Slice(count));
		}

		return count;
	}

	// Four candidates from each 2 bytes, the low half of a byte first: a 16-bit product moves half-byte i to bits 12 to 15 of lane i. A
	// byte shuffle looks up b mod 5 for η = 2 or b for η = 4, and one from RejectShuffles moves η minus those of the accepted candidates
	// to the front of a whole vector, which goes to destination while four more fit; the scalar kernel takes the rest. The shuffle follows
	// only which candidates are rejected, which says nothing of the values, as MLDsaAvx2.RejectEta argues.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static int RejectEta(ReadOnlySpan<byte> source, Span<int> destination, int eta)
	{
		Debug.Assert(eta is 2 or 4);

		ref byte input = ref MemoryMarshal.GetReference(source);
		ref int output = ref MemoryMarshal.GetReference(destination);
		ref byte shuffles = ref MemoryMarshal.GetReference(RejectShuffles);
		Vector128<ushort> multipliers = Vector128.Create((ushort)4096, 0, 256, 0, 16, 0, 1, 0);
		Vector128<byte> remainders = eta is 2 ? Vector128.Create((byte)0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0) : Vector128<byte>.Indices;
		Vector128<int> bound = Vector128.Create(eta is 2 ? 15 : 9);
		Vector128<int> center = Vector128.Create(eta);
		int count = 0;
		int offset = 0;

		for (; offset <= source.Length - sizeof(ushort) && count <= destination.Length - Vector128<int>.Count; offset += sizeof(ushort))
		{
			Vector128<int> pair = Vector128.Create((int)Unsafe.ReadUnaligned<ushort>(ref Unsafe.Add(ref input, offset)));
			Vector128<int> b = (pair.AsUInt16() * multipliers).AsInt32() >>> 12;
			uint accepted = ExtractMask(Vector128.LessThan(b, bound));
			Vector128<int> values = center - Vector128.ShuffleNative(remainders, b.AsByte()).AsInt32();
			Vector128.ShuffleNative(values.AsByte(), Vector128.LoadUnsafe(ref shuffles, 16 * accepted)).AsInt32().StoreUnsafe(ref output, (nuint)count);
			count += BitOperations.PopCount(accepted);
		}

		if (count < destination.Length)
		{
			count += MLDsaScalar.RejectEta(source.Slice(offset), destination.Slice(count), eta);
		}

		return count;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void EncodeT1(ReadOnlySpan<int> t1, Span<byte> destination)
	{
		Debug.Assert(t1.Length is N && destination.Length >= 320);

		PackWide(ref MemoryMarshal.GetReference(t1), ref MemoryMarshal.GetReference(destination), 10, 0, false);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void DecodeT1(ReadOnlySpan<byte> source, Span<int> f)
	{
		Debug.Assert(source.Length >= 320 && f.Length is N);

		ref byte input = ref MemoryMarshal.GetReference(source);
		ref int output = ref MemoryMarshal.GetReference(f);
		Vector128<byte> fields = Vector128.Create(0, 1, 0x80, 0x80, 1, 2, 0x80, 0x80, 2, 3, 0x80, 0x80, 3, 4, 0x80, 0x80);
		Vector128<uint> multipliers = Vector128.Create(1u << 7, 1 << 5, 1 << 3, 1 << 1);

		for (int i = 0; i < 64; ++i)
		{
			(Unpack(ref input, 5 * i, 10, fields, multipliers) << D).StoreUnsafe(ref output, (nuint)(4 * i));
		}
	}

	// 13 bits make the joints of the values fall at every bit position, and only key generation packs t0; the scalar kernel does it.
	public static void EncodeT0(ReadOnlySpan<int> t0, Span<byte> destination)
	{
		MLDsaScalar.EncodeT0(t0, destination);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void EncodeEta(ReadOnlySpan<int> s, Span<byte> destination, int eta)
	{
		Debug.Assert(eta is 2 or 4);
		Debug.Assert(s.Length is N && destination.Length >= 32 * (eta is 2 ? 3 : 4));

		ref int source = ref MemoryMarshal.GetReference(s);
		ref byte target = ref MemoryMarshal.GetReference(destination);

		if (eta is 2)
		{
			Pack3(ref source, ref target, 2);
		}
		else
		{
			Pack4(ref source, ref target, 4, true);
		}
	}

	// The check gathers 2η − v of every value with or, as MLDsaScalar.DecodeEta does.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static bool DecodeEta(ReadOnlySpan<byte> source, Span<int> s, int eta)
	{
		Debug.Assert(eta is 2 or 4);
		Debug.Assert(source.Length >= 32 * (eta is 2 ? 3 : 4) && s.Length is N);

		ref byte input = ref MemoryMarshal.GetReference(source);
		ref int output = ref MemoryMarshal.GetReference(s);

		if (eta is 2)
		{
			Vector128<byte> lowFields = Vector128.Create(0, 0x80, 0x80, 0x80, 0, 0x80, 0x80, 0x80, 0, 1, 0x80, 0x80, 1, 0x80, 0x80, 0x80);
			Vector128<byte> highFields = Vector128.Create(0, 0x80, 0x80, 0x80, 0, 1, 0x80, 0x80, 1, 0x80, 0x80, 0x80, 1, 0x80, 0x80, 0x80);
			Vector128<uint> lowMultipliers = Vector128.Create(1u << 7, 1 << 4, 1 << 1, 1 << 6);
			Vector128<uint> highMultipliers = Vector128.Create(1u << 3, 1 << 0, 1 << 5, 1 << 2);
			return DecodeEta(ref input, ref output, 2, 3, lowFields, highFields, lowMultipliers, highMultipliers);
		}
		else
		{
			Vector128<byte> fields = Vector128.Create(0, 0x80, 0x80, 0x80, 0, 0x80, 0x80, 0x80, 1, 0x80, 0x80, 0x80, 1, 0x80, 0x80, 0x80);
			Vector128<uint> multipliers = Vector128.Create(1u << 7, 1 << 3, 1 << 7, 1 << 3);
			return DecodeEta(ref input, ref output, 4, 4, fields, fields, multipliers, multipliers);
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void EncodeZ(ReadOnlySpan<int> z, Span<byte> destination, int gamma1Bits)
	{
		Debug.Assert(gamma1Bits is 17 or 19);
		Debug.Assert(z.Length is N && destination.Length >= 32 * (gamma1Bits + 1));

		ref int source = ref MemoryMarshal.GetReference(z);
		ref byte target = ref MemoryMarshal.GetReference(destination);

		if (gamma1Bits is 17)
		{
			PackWide(ref source, ref target, 18, 1 << 17, true);
		}
		else
		{
			PackWide(ref source, ref target, 20, 1 << 19, true);
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void DecodeZ(ReadOnlySpan<byte> source, Span<int> z, int gamma1Bits)
	{
		Debug.Assert(gamma1Bits is 17 or 19);
		Debug.Assert(source.Length >= 32 * (gamma1Bits + 1) && z.Length is N);

		ref byte input = ref MemoryMarshal.GetReference(source);
		ref int output = ref MemoryMarshal.GetReference(z);

		if (gamma1Bits is 17)
		{
			Vector128<byte> fields = Vector128.Create(0, 1, 2, 0x80, 2, 3, 4, 0x80, 4, 5, 6, 0x80, 6, 7, 8, 0x80);
			DecodeZ(ref input, ref output, 18, fields, Vector128.Create(1u << 7, 1 << 5, 1 << 3, 1 << 1));
		}
		else
		{
			Vector128<byte> fields = Vector128.Create(0, 1, 2, 0x80, 2, 3, 4, 0x80, 5, 6, 7, 0x80, 7, 8, 9, 0x80);
			DecodeZ(ref input, ref output, 20, fields, Vector128.Create(1u << 7, 1 << 3, 1 << 7, 1 << 3));
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void EncodeW1(ReadOnlySpan<int> w1, Span<byte> destination, int gamma2)
	{
		Debug.Assert(gamma2 is MLDsaConstants.Gamma2Small or MLDsaConstants.Gamma2Large);
		Debug.Assert(w1.Length is N && destination.Length >= 32 * (gamma2 is MLDsaConstants.Gamma2Small ? 6 : 4));

		ref int source = ref MemoryMarshal.GetReference(w1);
		ref byte target = ref MemoryMarshal.GetReference(destination);

		if (gamma2 is MLDsaConstants.Gamma2Small)
		{
			Pack6(ref source, ref target);
		}
		else
		{
			Pack4(ref source, ref target, 0, false);
		}
	}

	// Layers 7 and 8 of NTT on the eight coefficients of a and b. The 32-bit interleavings of a and b hold the pairs of layer 7, those of
	// the results the pairs of layer 8, and those of these a and b again.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void NttPair(ref Vector128<int> a, ref Vector128<int> b, ref int zetas)
	{
		Interleave(ref a, ref b);
		Butterfly(ref a, ref b, ref zetas);
		Interleave(ref a, ref b);
		Butterfly(ref a, ref b, ref Unsafe.Add(ref zetas, 16));
		Interleave(ref a, ref b);
	}

	// Layers 1 and 2 of NTT⁻¹ on the eight coefficients of a and b, each Deinterleave undoing an Interleave of NttPair.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseNttPair(ref Vector128<int> a, ref Vector128<int> b, ref int zetas)
	{
		Deinterleave(ref a, ref b);
		InverseButterfly(ref a, ref b, ref zetas);
		Deinterleave(ref a, ref b);
		InverseButterfly(ref a, ref b, ref Unsafe.Add(ref zetas, 16));
		Deinterleave(ref a, ref b);
	}

	// The butterfly of NTT (Algorithm 41) with Zetas[index] in every lane.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Butterfly(ref Vector128<int> low, ref Vector128<int> high, nint index)
	{
		Vector128<int> zeta = Vector128.Create(Unsafe.Add(ref MemoryMarshal.GetReference(MLDsaConstants.Zetas), index));
		Vector128<int> zetaQInverse = Vector128.Create(Unsafe.Add(ref MemoryMarshal.GetReference(MLDsaConstants.ZetasQInverse), index));
		Vector128<int> t = MultiplyMontgomery(high, zeta, zetaQInverse, zeta, zetaQInverse);
		high = low - t;
		low += t;
	}

	// The butterfly of NTT with the line of zetas at zetas.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Butterfly(ref Vector128<int> low, ref Vector128<int> high, ref int zetas)
	{
		Vector128<int> t = MultiplyMontgomery(high, ref zetas);
		high = low - t;
		low += t;
	}

	// The butterfly of NTT⁻¹ (Algorithm 42), its (low − high) · (−Zetas[index]) taken as (high − low) · Zetas[index].
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseButterfly(ref Vector128<int> low, ref Vector128<int> high, nint index)
	{
		Vector128<int> zeta = Vector128.Create(Unsafe.Add(ref MemoryMarshal.GetReference(MLDsaConstants.Zetas), index));
		Vector128<int> zetaQInverse = Vector128.Create(Unsafe.Add(ref MemoryMarshal.GetReference(MLDsaConstants.ZetasQInverse), index));
		Vector128<int> difference = high - low;
		low += high;
		high = MultiplyMontgomery(difference, zeta, zetaQInverse, zeta, zetaQInverse);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseButterfly(ref Vector128<int> low, ref Vector128<int> high, ref int zetas)
	{
		Vector128<int> difference = high - low;
		low += high;
		high = MultiplyMontgomery(difference, ref zetas);
	}

	// Layer 8 of NTT⁻¹ with the factor that ends it.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LastInverseButterfly(ref Vector128<int> low, ref Vector128<int> high)
	{
		Vector128<int> factor = Vector128.Create(MLDsaConstants.InverseNttFactor);
		Vector128<int> factorQInverse = Vector128.Create(MLDsaConstants.InverseNttFactorQInverse);
		Vector128<int> zeta = Vector128.Create(MLDsaConstants.LastInverseZeta);
		Vector128<int> zetaQInverse = Vector128.Create(MLDsaConstants.LastInverseZetaQInverse);
		Vector128<int> difference = high - low;
		low = MultiplyMontgomery(low + high, factor, factorQInverse, factor, factorQInverse);
		high = MultiplyMontgomery(difference, zeta, zetaQInverse, zeta, zetaQInverse);
	}

	// With a line of zetas: ζ of every lane, ζ · q⁻¹ mod 2^32, and both of the odd lanes in the even lanes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<int> MultiplyMontgomery(Vector128<int> a, ref int zetas)
	{
		Vector128<int> zeta = Vector128.LoadUnsafe(ref zetas);
		Vector128<int> zetaQInverse = Vector128.LoadUnsafe(ref zetas, 4);

		if (Sse41.IsSupported)
		{
			return MultiplyMontgomery(a, zeta, zetaQInverse, Vector128.LoadUnsafe(ref zetas, 8), Vector128.LoadUnsafe(ref zetas, 12));
		}

		return MultiplyMontgomery(a, zeta, zetaQInverse, zeta, zetaQInverse);
	}

	// a · ζ · R⁻¹ mod q in (−q, q) for |ζ| < q / 2. SSE4.1 takes ζ of the even lanes from the even lanes of zeta and ζ of the odd lanes
	// from the even lanes of zetaOdd, AdvSimd every ζ from zeta, each with its ζ · q⁻¹ mod 2^32.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<int> MultiplyMontgomery(Vector128<int> a, Vector128<int> zeta, Vector128<int> zetaQInverse, Vector128<int> zetaOdd, Vector128<int> zetaOddQInverse)
	{
		Vector128<int> q = Vector128.Create(Q);

		if (Sse41.IsSupported)
		{
			// The 64-bit differences have zero low halves, so their high halves join with an or.
			Vector128<int> aOdd = Odd(a);
			Vector128<long> even = Sse41.Multiply(a, zeta) - Sse41.Multiply(Sse41.Multiply(a, zetaQInverse).AsInt32(), q);
			Vector128<long> odd = Sse41.Multiply(aOdd, zetaOdd) - Sse41.Multiply(Sse41.Multiply(aOdd, zetaOddQInverse).AsInt32(), q);
			return (even.AsUInt64() >>> 32).AsInt32() | odd.AsInt32();
		}

		// With t = a · ζ · q⁻¹ mod 2^32, a · ζ and t · q agree in the low 32 bits, so the doubled high halves that sqdmulh
		// gives differ by exactly twice the result.
		Vector128<int> high = AdvSimd.MultiplyDoublingSaturateHigh(a, zeta);
		return AdvSimd.FusedSubtractHalving(high, AdvSimd.MultiplyDoublingSaturateHigh(a * zetaQInverse, q));
	}

	// The 64-bit products of u and v, returned for first and set in second as MultiplyAccumulate sums them.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<long> Multiply(Vector128<int> u, Vector128<int> v, out Vector128<long> second)
	{
		if (Sse41.IsSupported)
		{
			second = Sse41.Multiply(Odd(u), Odd(v));
			return Sse41.Multiply(u, v);
		}

		second = AdvSimd.MultiplyWideningUpper(u, v);
		return AdvSimd.MultiplyWideningLower(u.GetLower(), v.GetLower());
	}

	// Adds the 64-bit products of u and v to first and second as MultiplyAccumulate sums them.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MultiplyAdd(ref Vector128<long> first, ref Vector128<long> second, Vector128<int> u, Vector128<int> v)
	{
		if (Sse41.IsSupported)
		{
			first += Sse41.Multiply(u, v);
			second += Sse41.Multiply(Odd(u), Odd(v));
		}
		else
		{
			first = AdvSimd.MultiplyWideningLowerAndAdd(first, u.GetLower(), v.GetLower());
			second = AdvSimd.MultiplyWideningUpperAndAdd(second, u, v);
		}
	}

	// R⁻¹ · c mod q in (−q, q) for |c| < 2^31 · q, with c of the lanes in first and second as MultiplyAccumulate sums them.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<int> MontgomeryReduce(Vector128<long> first, Vector128<long> second)
	{
		Vector128<int> q = Vector128.Create(Q);
		Vector128<int> qInverse = Vector128.Create(MLDsaConstants.QInverse);

		if (Sse41.IsSupported)
		{
			first -= Sse41.Multiply(Sse41.Multiply(first.AsInt32(), qInverse).AsInt32(), q);
			second -= Sse41.Multiply(Sse41.Multiply(second.AsInt32(), qInverse).AsInt32(), q);
			return (first.AsUInt64() >>> 32).AsInt32() | second.AsInt32();
		}

		Vector128<int> t = AdvSimd.Arm64.UnzipEven(first.AsInt32(), second.AsInt32()) * qInverse;
		first = AdvSimd.MultiplyWideningLowerAndSubtract(first, t.GetLower(), q.GetLower());
		second = AdvSimd.MultiplyWideningUpperAndSubtract(second, t, q);
		return AdvSimd.Arm64.UnzipOdd(first.AsInt32(), second.AsInt32());
	}

	// The odd lanes moved down into the even lanes, which pmuldq reads.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<int> Odd(Vector128<int> a)
	{
		return (a.AsInt64() >>> 32).AsInt32();
	}

	// MLDsaScalar.Reduce32 in every lane.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<int> Reduce(Vector128<int> a)
	{
		Vector128<int> quotient = a + Vector128.Create(1 << 22) >> 23;
		return a - quotient * Vector128.Create(Q);
	}

	// Maps (−q, q) to [0, q).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<int> ToCanonical(Vector128<int> a)
	{
		return a + (a >> 31 & Vector128.Create(Q));
	}

	// MLDsaScalar.Decompose in every lane.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<int> Decompose(Vector128<int> r, int gamma2, out Vector128<int> r0)
	{
		Vector128<int> a = ToCanonical(r);
		Vector128<int> a1 = a + Vector128.Create(127) >> 7;

		if (gamma2 is MLDsaConstants.Gamma2Large)
		{
			a1 = a1 * Vector128.Create(1025) + Vector128.Create(1 << 21) >> 22 & Vector128.Create(15);
		}
		else
		{
			a1 = a1 * Vector128.Create(11275) + Vector128.Create(1 << 23) >> 24;
			a1 ^= Vector128.Create(43) - a1 >> 31 & a1;
		}

		r0 = a - a1 * Vector128.Create(2 * gamma2);
		r0 -= Vector128.Create((Q - 1) / 2) - r0 >> 31 & Vector128.Create(Q);
		return a1;
	}

	// Taken as four 32-bit units each: (a, b) ← ([a0, b0, a1, b1], [a2, b2, a3, b3]).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Interleave(ref Vector128<int> a, ref Vector128<int> b)
	{
		Vector128<uint> x = a.AsUInt32();
		Vector128<uint> y = b.AsUInt32();
		a = VectorTranspose.ZipLow(x, y).AsInt32();
		b = VectorTranspose.ZipHigh(x, y).AsInt32();
	}

	// The inverse of Interleave: (a, b) ← ([a0, a2, b0, b2], [a1, a3, b1, b3]).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Deinterleave(ref Vector128<int> a, ref Vector128<int> b)
	{
		if (Sse.IsSupported)
		{
			Vector128<float> x = a.AsSingle();
			Vector128<float> y = b.AsSingle();
			a = Sse.Shuffle(x, y, 0b10_00_10_00).AsInt32();
			b = Sse.Shuffle(x, y, 0b11_01_11_01).AsInt32();
		}
		else
		{
			Vector128<int> x = a;
			a = AdvSimd.Arm64.UnzipEven(x, b);
			b = AdvSimd.Arm64.UnzipOdd(x, b);
		}
	}

	// Bit i set for each lane i of the mask that is set.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint ExtractMask(Vector128<int> mask)
	{
		if (AdvSimd.Arm64.IsSupported)
		{
			return (uint)AdvSimd.Arm64.AddAcross(mask & Vector128.Create(1, 2, 4, 8)).ToScalar();
		}

		return mask.ExtractMostSignificantBits();
	}

	// The four values of bits bits from byte start of the 32 · bits bytes at source, from the 16 bytes at start, moved back to end
	// with the source where they would pass it. fields picks the bytes of each value into its 32-bit lane, 0x80 marking those left
	// zero, which the move keeps out of range, and multipliers, 2^(7 − s) for a value at bit s of them, moves it to bit 7, from where
	// the shift brings it down; the bits above are masked off.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<int> Unpack(ref byte source, int start, [ConstantExpected(Min = 3, Max = 20)] int bits, Vector128<byte> fields, Vector128<uint> multipliers)
	{
		int offset = Math.Min(start, 32 * bits - 16);
		Vector128<byte> indices = fields + Vector128.Create((byte)(start - offset));
		Vector128<uint> values = Vector128.ShuffleNative(Vector128.LoadUnsafe(ref source, (nuint)offset), indices).AsUInt32() * multipliers >>> 7;
		return (values & Vector128.Create((1u << bits) - 1)).AsInt32();
	}

	// Each eight values come from bits bytes, values 4 to 7 from byte bits / 2 on.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool DecodeEta(ref byte source, ref int destination, [ConstantExpected] int eta, [ConstantExpected(Min = 3, Max = 4)] int bits, Vector128<byte> lowFields, Vector128<byte> highFields, Vector128<uint> lowMultipliers, Vector128<uint> highMultipliers)
	{
		Vector128<int> inRange = Vector128<int>.Zero;

		for (int i = 0; i < 32; ++i)
		{
			Vector128<int> low = Unpack(ref source, bits * i, bits, lowFields, lowMultipliers);
			Vector128<int> high = Unpack(ref source, bits * i + bits / 2, bits, highFields, highMultipliers);
			inRange |= Vector128.Create(2 * eta) - low | Vector128.Create(2 * eta) - high;
			(Vector128.Create(eta) - low).StoreUnsafe(ref destination, (nuint)(8 * i));
			(Vector128.Create(eta) - high).StoreUnsafe(ref destination, (nuint)(8 * i + 4));
		}

		return !Vector128.LessThanAny(inRange, Vector128<int>.Zero);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void DecodeZ(ref byte source, ref int destination, [ConstantExpected(Min = 18, Max = 20)] int bits, Vector128<byte> fields, Vector128<uint> multipliers)
	{
		for (int i = 0; i < 64; ++i)
		{
			Vector128<int> values = Unpack(ref source, bits / 2 * i, bits, fields, multipliers);
			(Vector128.Create(1 << bits - 1) - values).StoreUnsafe(ref destination, (nuint)(4 * i));
		}
	}

	// Values of bits bits, bits even and at least 10: bias − f_i, or f_i without subtract. Each value moves to its bit within its first
	// byte, and the bytes of the even and of the odd values, which do not overlap, gather with a shuffle each into bits / 2 bytes. Stores
	// of 16 bytes overrun into the next, which overwrites them, but for those near the end.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PackWide(ref int source, ref byte destination, [ConstantExpected(Min = 10, Max = 20)] int bits, int bias, bool subtract)
	{
		Vector128<byte> evenFields;
		Vector128<byte> oddFields;
		Vector128<uint> multipliers;

		switch (bits)
		{
			case 10:
			{
				evenFields = Vector128.Create(0, 1, 8, 9, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero);
				oddFields = Vector128.Create(Zero, 4, 5, 12, 13, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero);
				multipliers = Vector128.Create(1u, 1 << 2, 1 << 4, 1 << 6);
				break;
			}
			case 18:
			{
				evenFields = Vector128.Create(0, 1, 2, Zero, 8, 9, 10, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero);
				oddFields = Vector128.Create(Zero, Zero, 4, 5, 6, Zero, 12, 13, 14, Zero, Zero, Zero, Zero, Zero, Zero, Zero);
				multipliers = Vector128.Create(1u, 1 << 2, 1 << 4, 1 << 6);
				break;
			}
			default:
			{
				evenFields = Vector128.Create(0, 1, 2, Zero, Zero, 8, 9, 10, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero);
				oddFields = Vector128.Create(Zero, Zero, 4, 5, 6, Zero, Zero, 12, 13, 14, Zero, Zero, Zero, Zero, Zero, Zero);
				multipliers = Vector128.Create(1u, 1 << 4, 1, 1 << 4);
				break;
			}
		}

		int length = bits / 2;

		for (int i = 0; i < 64; ++i)
		{
			Vector128<int> values = Vector128.LoadUnsafe(ref source, (nuint)(4 * i));

			if (subtract)
			{
				values = Vector128.Create(bias) - values;
			}

			Vector128<byte> shifted = (values.AsUInt32() * multipliers).AsByte();
			Vector128<byte> packed = Vector128.Shuffle(shifted, evenFields) | Vector128.Shuffle(shifted, oddFields);
			int offset = length * i;

			if (offset <= 32 * bits - 16)
			{
				packed.StoreUnsafe(ref destination, (nuint)offset);
			}
			else
			{
				StorePartial(packed, ref Unsafe.Add(ref destination, offset), length);
			}
		}
	}

	// The first length bytes of value.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StorePartial(Vector128<byte> value, ref byte destination, int length)
	{
		if (length is 5)
		{
			Unsafe.WriteUnaligned(ref destination, value.AsUInt32().ToScalar());
			Unsafe.Add(ref destination, 4) = value.GetElement(4);
			return;
		}

		Unsafe.WriteUnaligned(ref destination, value.AsUInt64().ToScalar());

		switch (length)
		{
			case 9:
			{
				Unsafe.Add(ref destination, 8) = value.GetElement(8);
				break;
			}
			case 10:
			{
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 8), value.AsUInt16().GetElement(4));
				break;
			}
			default:
			{
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 8), value.AsUInt32().GetElement(2));
				break;
			}
		}
	}

	// The 16 values at source in order as bytes, bias − f_i or f_i without subtract, each below 256.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> LoadBytes(ref int source, int bias, bool subtract)
	{
		Vector128<int> v0 = Vector128.LoadUnsafe(ref source);
		Vector128<int> v1 = Vector128.LoadUnsafe(ref source, 4);
		Vector128<int> v2 = Vector128.LoadUnsafe(ref source, 8);
		Vector128<int> v3 = Vector128.LoadUnsafe(ref source, 12);

		if (subtract)
		{
			Vector128<int> b = Vector128.Create(bias);
			v0 = b - v0;
			v1 = b - v1;
			v2 = b - v2;
			v3 = b - v3;
		}

		return Vector128.Narrow(Vector128.Narrow(v0, v1).AsUInt16(), Vector128.Narrow(v2, v3).AsUInt16());
	}

	// Each 32 values below 8 make 12 bytes: pairs of bytes join into 6 bits, pairs of these into 12 and pairs of those into the three
	// low bytes of each 64-bit lane, of which a shuffle gathers six bytes from each 16 values.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Pack3(ref int source, ref byte destination, int bias)
	{
		for (nuint i = 0; i < 8; ++i)
		{
			Vector128<byte> low = Vector128.Shuffle(Join3(LoadBytes(ref Unsafe.Add(ref source, 32 * i), bias, true)), Vector128.Create(0, 1, 2, 8, 9, 10, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero));
			Vector128<byte> high = Vector128.Shuffle(Join3(LoadBytes(ref Unsafe.Add(ref source, 32 * i + 16), bias, true)), Vector128.Create(Zero, Zero, Zero, Zero, Zero, Zero, 0, 1, 2, 8, 9, 10, Zero, Zero, Zero, Zero));
			Vector128<byte> packed = low | high;

			if (i < 7)
			{
				packed.StoreUnsafe(ref destination, 12 * i);
			}
			else
			{
				StorePartial(packed, ref Unsafe.Add(ref destination, 84), 12);
			}
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> Join3(Vector128<byte> bytes)
	{
		Vector128<ushort> w = bytes.AsUInt16();
		Vector128<uint> d = (w & Vector128.Create((ushort)0x07) | w >>> 5 & Vector128.Create((ushort)0x38)).AsUInt32();
		Vector128<ulong> e = (d & Vector128.Create(0x3Fu) | d >>> 10 & Vector128.Create(0xFC0u)).AsUInt64();
		return (e & Vector128.Create(0xFFFUL) | e >>> 20 & Vector128.Create(0xFFF000UL)).AsByte();
	}

	// Each 32 values below 16 make 16 bytes, a pair per byte.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Pack4(ref int source, ref byte destination, int bias, bool subtract)
	{
		for (nuint i = 0; i < 8; ++i)
		{
			Vector128<ushort> low = Join4(LoadBytes(ref Unsafe.Add(ref source, 32 * i), bias, subtract));
			Vector128<ushort> high = Join4(LoadBytes(ref Unsafe.Add(ref source, 32 * i + 16), bias, subtract));
			Vector128.Narrow(low, high).StoreUnsafe(ref destination, 16 * i);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ushort> Join4(Vector128<byte> bytes)
	{
		Vector128<ushort> w = bytes.AsUInt16();
		return w & Vector128.Create((ushort)0x0F) | w >>> 4 & Vector128.Create((ushort)0xF0);
	}

	// Each 16 values below 64 make 12 bytes: pairs of bytes join into 12 bits and pairs of these into the three low bytes of
	// each 32-bit lane, which a shuffle gathers.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Pack6(ref int source, ref byte destination)
	{
		Vector128<byte> fields = Vector128.Create(0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, Zero, Zero, Zero, Zero);

		for (nuint i = 0; i < 16; ++i)
		{
			Vector128<ushort> w = LoadBytes(ref Unsafe.Add(ref source, 16 * i), 0, false).AsUInt16();
			Vector128<uint> d = (w & Vector128.Create((ushort)0x3F) | w >>> 2 & Vector128.Create((ushort)0xFC0)).AsUInt32();
			Vector128<byte> packed = Vector128.Shuffle((d & Vector128.Create(0xFFFu) | d >>> 4 & Vector128.Create(0xFFF000u)).AsByte(), fields);

			if (i < 15)
			{
				packed.StoreUnsafe(ref destination, 12 * i);
			}
			else
			{
				StorePartial(packed, ref Unsafe.Add(ref destination, 180), 12);
			}
		}
	}
}
