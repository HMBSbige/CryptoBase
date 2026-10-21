using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Signatures.MLDsa;

// Eight coefficients per 256-bit vector. vpmuldq multiplies only the even 32-bit lanes into 64 bits, so a product of two vectors takes
// it once for the even lanes and once for the odd lanes moved down. Encoders and decoders never access past the end of a buffer. The
// operations that loop or hold many vectors are not inlined, as merged into a large caller their vectors end up on the stack.
internal readonly partial struct MLDsaAvx2 : IMLDsaKernel
{
	private const int N = MLDsaConstants.N;
	private const int Q = MLDsaConstants.Q;
	private const int D = MLDsaConstants.D;

	public static bool IsSupported => Avx2.IsSupported;

	// Layers 1 to 3 run on eight vectors 32 coefficients apart, layers 4 to 8 on four consecutive ones. A product by a zeta is below q,
	// so eight layers keep the coefficients below 9q without reduction.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void Ntt(Span<int> f)
	{
		Debug.Assert(f.Length is N);

		ref Vector256<int> coefficients = ref Unsafe.As<int, Vector256<int>>(ref MemoryMarshal.GetReference(f));
		ref Vector256<int> zetas = ref Unsafe.As<int, Vector256<int>>(ref MemoryMarshal.GetReference(NttZetas));

		for (nint i = 0; i < 4; ++i)
		{
			ref Vector256<int> column = ref Unsafe.Add(ref coefficients, i);
			Vector256<int> v0 = column;
			Vector256<int> v1 = Unsafe.Add(ref column, 4);
			Vector256<int> v2 = Unsafe.Add(ref column, 8);
			Vector256<int> v3 = Unsafe.Add(ref column, 12);
			Vector256<int> v4 = Unsafe.Add(ref column, 16);
			Vector256<int> v5 = Unsafe.Add(ref column, 20);
			Vector256<int> v6 = Unsafe.Add(ref column, 24);
			Vector256<int> v7 = Unsafe.Add(ref column, 28);

			Butterfly(ref v0, ref v4, 1);
			Butterfly(ref v1, ref v5, 1);
			Butterfly(ref v2, ref v6, 1);
			Butterfly(ref v3, ref v7, 1);

			Butterfly(ref v0, ref v2, 2);
			Butterfly(ref v1, ref v3, 2);
			Butterfly(ref v4, ref v6, 3);
			Butterfly(ref v5, ref v7, 3);

			Butterfly(ref v0, ref v1, 4);
			Butterfly(ref v2, ref v3, 5);
			Butterfly(ref v4, ref v5, 6);
			Butterfly(ref v6, ref v7, 7);

			column = v0;
			Unsafe.Add(ref column, 4) = v1;
			Unsafe.Add(ref column, 8) = v2;
			Unsafe.Add(ref column, 12) = v3;
			Unsafe.Add(ref column, 16) = v4;
			Unsafe.Add(ref column, 20) = v5;
			Unsafe.Add(ref column, 24) = v6;
			Unsafe.Add(ref column, 28) = v7;
		}

		for (nint i = 0; i < 8; ++i)
		{
			ref Vector256<int> block = ref Unsafe.Add(ref coefficients, 4 * i);
			Vector256<int> v0 = block;
			Vector256<int> v1 = Unsafe.Add(ref block, 1);
			Vector256<int> v2 = Unsafe.Add(ref block, 2);
			Vector256<int> v3 = Unsafe.Add(ref block, 3);

			Butterfly(ref v0, ref v2, 8 + i);
			Butterfly(ref v1, ref v3, 8 + i);
			Butterfly(ref v0, ref v1, 16 + 2 * i);
			Butterfly(ref v2, ref v3, 17 + 2 * i);
			NttPair(ref v0, ref v1, ref Unsafe.Add(ref zetas, 24 * i));
			NttPair(ref v2, ref v3, ref Unsafe.Add(ref zetas, 24 * i + 12));

			block = v0;
			Unsafe.Add(ref block, 1) = v1;
			Unsafe.Add(ref block, 2) = v2;
			Unsafe.Add(ref block, 3) = v3;
		}
	}

	// The mirror of Ntt. The sums double in each layer, so they stay below 256q < 2^31 without reduction.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void InverseNtt(Span<int> f)
	{
		Debug.Assert(f.Length is N);

		ref Vector256<int> coefficients = ref Unsafe.As<int, Vector256<int>>(ref MemoryMarshal.GetReference(f));
		ref Vector256<int> zetas = ref Unsafe.As<int, Vector256<int>>(ref MemoryMarshal.GetReference(InverseNttZetas));

		for (nint i = 0; i < 8; ++i)
		{
			ref Vector256<int> block = ref Unsafe.Add(ref coefficients, 4 * i);
			Vector256<int> v0 = block;
			Vector256<int> v1 = Unsafe.Add(ref block, 1);
			Vector256<int> v2 = Unsafe.Add(ref block, 2);
			Vector256<int> v3 = Unsafe.Add(ref block, 3);

			InverseNttPair(ref v0, ref v1, ref Unsafe.Add(ref zetas, 24 * i));
			InverseNttPair(ref v2, ref v3, ref Unsafe.Add(ref zetas, 24 * i + 12));
			InverseButterfly(ref v0, ref v1, 31 - 2 * i);
			InverseButterfly(ref v2, ref v3, 30 - 2 * i);
			InverseButterfly(ref v0, ref v2, 15 - i);
			InverseButterfly(ref v1, ref v3, 15 - i);

			block = v0;
			Unsafe.Add(ref block, 1) = v1;
			Unsafe.Add(ref block, 2) = v2;
			Unsafe.Add(ref block, 3) = v3;
		}

		for (nint i = 0; i < 4; ++i)
		{
			ref Vector256<int> column = ref Unsafe.Add(ref coefficients, i);
			Vector256<int> v0 = column;
			Vector256<int> v1 = Unsafe.Add(ref column, 4);
			Vector256<int> v2 = Unsafe.Add(ref column, 8);
			Vector256<int> v3 = Unsafe.Add(ref column, 12);
			Vector256<int> v4 = Unsafe.Add(ref column, 16);
			Vector256<int> v5 = Unsafe.Add(ref column, 20);
			Vector256<int> v6 = Unsafe.Add(ref column, 24);
			Vector256<int> v7 = Unsafe.Add(ref column, 28);

			InverseButterfly(ref v0, ref v1, 7);
			InverseButterfly(ref v2, ref v3, 6);
			InverseButterfly(ref v4, ref v5, 5);
			InverseButterfly(ref v6, ref v7, 4);

			InverseButterfly(ref v0, ref v2, 3);
			InverseButterfly(ref v1, ref v3, 3);
			InverseButterfly(ref v4, ref v6, 2);
			InverseButterfly(ref v5, ref v7, 2);

			LastInverseButterfly(ref v0, ref v4);
			LastInverseButterfly(ref v1, ref v5);
			LastInverseButterfly(ref v2, ref v6);
			LastInverseButterfly(ref v3, ref v7);

			column = v0;
			Unsafe.Add(ref column, 4) = v1;
			Unsafe.Add(ref column, 8) = v2;
			Unsafe.Add(ref column, 12) = v3;
			Unsafe.Add(ref column, 16) = v4;
			Unsafe.Add(ref column, 20) = v5;
			Unsafe.Add(ref column, 24) = v6;
			Unsafe.Add(ref column, 28) = v7;
		}
	}

	// The products of the even and of the odd lanes sum apart in 64 bits. A product is below 9q², so the sum of eight stays below 2^31 · q, the input
	// bound of MontgomeryReduce. Each pass takes two vectors through all the polynomials, and the products of the first polynomial start the sums.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void MultiplyAccumulate(ReadOnlySpan<int> a, ReadOnlySpan<int> b, Span<int> destination, int count)
	{
		Debug.Assert(count is >= 1 and <= 8);
		Debug.Assert(a.Length >= count * N && b.Length >= count * N && destination.Length is N);

		ref int x = ref MemoryMarshal.GetReference(a);
		ref int y = ref MemoryMarshal.GetReference(b);
		ref int z = ref MemoryMarshal.GetReference(destination);
		nuint end = (nuint)count * N;

		for (nuint i = 0; i < N; i += 16)
		{
			Vector256<int> u0 = Vector256.LoadUnsafe(ref x, i);
			Vector256<int> v0 = Vector256.LoadUnsafe(ref y, i);
			Vector256<int> u1 = Vector256.LoadUnsafe(ref x, i + 8);
			Vector256<int> v1 = Vector256.LoadUnsafe(ref y, i + 8);
			Vector256<long> even0 = Avx2.Multiply(u0, v0);
			Vector256<long> odd0 = Avx2.Multiply(Odd(u0), Odd(v0));
			Vector256<long> even1 = Avx2.Multiply(u1, v1);
			Vector256<long> odd1 = Avx2.Multiply(Odd(u1), Odd(v1));

			for (nuint j = i + N; j < end; j += N)
			{
				u0 = Vector256.LoadUnsafe(ref x, j);
				v0 = Vector256.LoadUnsafe(ref y, j);
				u1 = Vector256.LoadUnsafe(ref x, j + 8);
				v1 = Vector256.LoadUnsafe(ref y, j + 8);
				even0 += Avx2.Multiply(u0, v0);
				odd0 += Avx2.Multiply(Odd(u0), Odd(v0));
				even1 += Avx2.Multiply(u1, v1);
				odd1 += Avx2.Multiply(Odd(u1), Odd(v1));
			}

			MontgomeryReduce(even0, odd0).StoreUnsafe(ref z, i);
			MontgomeryReduce(even1, odd1).StoreUnsafe(ref z, i + 8);
		}
	}

	public static void Reduce(Span<int> f)
	{
		Debug.Assert(f.Length is N);

		ref int coefficients = ref MemoryMarshal.GetReference(f);

		for (nuint i = 0; i < N; i += 8)
		{
			Reduce(Vector256.LoadUnsafe(ref coefficients, i)).StoreUnsafe(ref coefficients, i);
		}
	}

	public static void Add(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination)
	{
		Debug.Assert(left.Length is N && right.Length is N && destination.Length is N);

		ref int x = ref MemoryMarshal.GetReference(left);
		ref int y = ref MemoryMarshal.GetReference(right);
		ref int z = ref MemoryMarshal.GetReference(destination);

		for (nuint i = 0; i < N; i += 8)
		{
			(Vector256.LoadUnsafe(ref x, i) + Vector256.LoadUnsafe(ref y, i)).StoreUnsafe(ref z, i);
		}
	}

	// As in MLDsaScalar.ExceedsBound, bound − 1 − |f_i| is negative exactly where the bound is reached; the signs gather with or.
	public static bool ExceedsBound(ReadOnlySpan<int> f, int bound)
	{
		Debug.Assert(f.Length is N && bound is > 0 and <= 2097409);

		ref int coefficients = ref MemoryMarshal.GetReference(f);
		Vector256<int> limit = Vector256.Create(bound - 1);
		Vector256<int> exceeded = Vector256<int>.Zero;

		for (nuint i = 0; i < N; i += 8)
		{
			exceeded |= limit - Vector256.Abs(Vector256.LoadUnsafe(ref coefficients, i));
		}

		return exceeded.ExtractMostSignificantBits() is not 0;
	}

	public static bool AddReduceExceedsBound(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination, int bound)
	{
		Debug.Assert(left.Length is N && right.Length is N && destination.Length is N && bound is > 0 and <= 2097409);

		ref int x = ref MemoryMarshal.GetReference(left);
		ref int y = ref MemoryMarshal.GetReference(right);
		ref int z = ref MemoryMarshal.GetReference(destination);
		Vector256<int> limit = Vector256.Create(bound - 1);
		Vector256<int> exceeded = Vector256<int>.Zero;

		for (nuint i = 0; i < N; i += 8)
		{
			Vector256<int> value = Reduce(Vector256.LoadUnsafe(ref x, i) + Vector256.LoadUnsafe(ref y, i));
			value.StoreUnsafe(ref z, i);
			exceeded |= limit - Vector256.Abs(value);
		}

		return exceeded.ExtractMostSignificantBits() is not 0;
	}

	public static bool SubtractReduceExceedsBound(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination, int bound)
	{
		Debug.Assert(left.Length is N && right.Length is N && destination.Length is N && bound is > 0 and <= 2097409);

		ref int x = ref MemoryMarshal.GetReference(left);
		ref int y = ref MemoryMarshal.GetReference(right);
		ref int z = ref MemoryMarshal.GetReference(destination);
		Vector256<int> limit = Vector256.Create(bound - 1);
		Vector256<int> exceeded = Vector256<int>.Zero;

		for (nuint i = 0; i < N; i += 8)
		{
			Vector256<int> value = Reduce(Vector256.LoadUnsafe(ref x, i) - Vector256.LoadUnsafe(ref y, i));
			value.StoreUnsafe(ref z, i);
			exceeded |= limit - Vector256.Abs(value);
		}

		return exceeded.ExtractMostSignificantBits() is not 0;
	}

	public static bool ReduceExceedsBound(Span<int> f, int bound)
	{
		Debug.Assert(f.Length is N && bound is > 0 and <= 2097409);

		ref int coefficients = ref MemoryMarshal.GetReference(f);
		Vector256<int> limit = Vector256.Create(bound - 1);
		Vector256<int> exceeded = Vector256<int>.Zero;

		for (nuint i = 0; i < N; i += 8)
		{
			Vector256<int> value = Reduce(Vector256.LoadUnsafe(ref coefficients, i));
			value.StoreUnsafe(ref coefficients, i);
			exceeded |= limit - Vector256.Abs(value);
		}

		return exceeded.ExtractMostSignificantBits() is not 0;
	}

	public static void Power2Round(ReadOnlySpan<int> t, Span<int> high, Span<int> low)
	{
		Debug.Assert(t.Length is N && high.Length is N && low.Length is N);

		ref int x = ref MemoryMarshal.GetReference(t);
		ref int y = ref MemoryMarshal.GetReference(high);
		ref int z = ref MemoryMarshal.GetReference(low);

		for (nuint i = 0; i < N; i += 8)
		{
			Vector256<int> r = ToCanonical(Reduce(Vector256.LoadUnsafe(ref x, i)));
			Vector256<int> r1 = r + Vector256.Create((1 << D - 1) - 1) >> D;
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

		for (nuint i = 0; i < N; i += 8)
		{
			Decompose(Vector256.LoadUnsafe(ref x, i), gamma2, out Vector256<int> r0).StoreUnsafe(ref y, i);
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
		Vector256<int> bound = Vector256.Create(gamma2);
		Vector256<int> count = Vector256<int>.Zero;

		for (nuint i = 0; i < N; i += 8)
		{
			Vector256<int> a0 = Vector256.LoadUnsafe(ref x, i);
			Vector256<int> a1 = Vector256.LoadUnsafe(ref y, i);
			Vector256<int> wrapped = Vector256.AndNot(Vector256.Equals(a0, -bound), Vector256.Equals(a1, Vector256<int>.Zero));
			Vector256<int> set = Vector256.GreaterThan(a0, bound) | Vector256.LessThan(a0, -bound) | wrapped;
			(-set).StoreUnsafe(ref z, i);
			count -= set;
		}

		return Vector256.Sum(count);
	}

	// As in MLDsaScalar.UseHint, with the step of the hint chosen by mask and wrapped modulo m in both directions.
	public static void UseHint(ReadOnlySpan<int> r, ReadOnlySpan<int> hint, Span<int> destination, int gamma2)
	{
		Debug.Assert(gamma2 is MLDsaConstants.Gamma2Small or MLDsaConstants.Gamma2Large);
		Debug.Assert(r.Length is N && hint.Length is N && destination.Length is N);

		ref int x = ref MemoryMarshal.GetReference(r);
		ref int y = ref MemoryMarshal.GetReference(hint);
		ref int z = ref MemoryMarshal.GetReference(destination);
		Vector256<int> m = Vector256.Create((Q - 1) / (2 * gamma2));

		for (nuint i = 0; i < N; i += 8)
		{
			Vector256<int> r1 = Decompose(Vector256.LoadUnsafe(ref x, i), gamma2, out Vector256<int> r0);
			Vector256<int> h = Vector256.LoadUnsafe(ref y, i);
			r1 += Vector256.ConditionalSelect(Vector256.GreaterThan(r0, Vector256<int>.Zero), h, -h);
			r1 += r1 >> 31 & m;
			r1 -= Vector256.GreaterThanOrEqual(r1, m) & m;
			r1.StoreUnsafe(ref z, i);
		}
	}

	// Eight candidates from 24 bytes, each 128-bit lane taking its 12 from the 16 bytes that end where they do; vpermd moves the accepted
	// ones to the front of a buffer that takes whole vectors. The bytes are public, so the permutation may depend on them.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static int RejectSample(ReadOnlySpan<byte> source, Span<int> destination)
	{
		Debug.Assert(source.Length % 3 is 0);

		const int GroupLength = 24;
		Span<int> buffer = stackalloc int[N + 8];
		ref byte input = ref MemoryMarshal.GetReference(source);
		ref int output = ref MemoryMarshal.GetReference(buffer);
		ref byte indices = ref MemoryMarshal.GetReference(RejectIndices);
		Vector256<byte> fields = Vector256.Create(0, 1, 2, 0x80, 3, 4, 5, 0x80, 6, 7, 8, 0x80, 9, 10, 11, 0x80, 4, 5, 6, 0x80, 7, 8, 9, 0x80, 10, 11, 12, 0x80, 13, 14, 15, 0x80);
		int limit = Math.Min(destination.Length, N);
		int count = 0;
		int offset = 0;

		for (; offset <= source.Length - GroupLength && count < limit; offset += GroupLength)
		{
			Vector256<byte> window = Vector256.Create(Vector128.LoadUnsafe(ref input, (nuint)offset), Vector128.LoadUnsafe(ref input, (nuint)offset + 8));
			Vector256<int> candidates = Avx2.Shuffle(window, fields).AsInt32() & Vector256.Create(0x7FFFFF);
			uint mask = Vector256.LessThan(candidates, Vector256.Create(Q)).ExtractMostSignificantBits();
			Vector128<byte> lanes = Vector128.CreateScalarUnsafe(Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref indices, 8 * mask))).AsByte();
			Avx2.PermuteVar8x32(candidates, Avx2.ConvertToVector256Int32(lanes)).StoreUnsafe(ref output, (nuint)count);
			count += BitOperations.PopCount(mask);
		}

		count = Math.Min(count, destination.Length);
		buffer.Slice(0, count).CopyTo(destination);

		if (count < destination.Length)
		{
			count += MLDsaScalar.RejectSample(source.Slice(offset), destination.Slice(count));
		}

		return count;
	}

	// Eight candidates from each 4 bytes, the low half of a byte first. A byte shuffle looks up b mod 5 for η = 2 or b for η = 4,
	// one from RejectIndices moves those of the accepted candidates to the front, and η minus them go to destination as a whole
	// vector while eight more fit; the scalar kernel takes the rest. The row of the table and the count follow which candidates are
	// rejected, and that pattern says nothing of the values: the half-bytes are independent and uniform, whether one is accepted
	// depends only on whether it is below the bound, and an accepted one is uniform over the accepted values whatever the others
	// are, so the pattern is independent of s1 and s2. Where the scalar kernel writes moves with the same pattern.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static int RejectEta(ReadOnlySpan<byte> source, Span<int> destination, int eta)
	{
		Debug.Assert(eta is 2 or 4);

		ref byte input = ref MemoryMarshal.GetReference(source);
		ref int output = ref MemoryMarshal.GetReference(destination);
		ref byte indices = ref MemoryMarshal.GetReference(RejectIndices);
		Vector128<byte> remainders = eta is 2 ? Vector128.Create((byte)0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0) : Vector128<byte>.Indices;
		Vector128<byte> low = Vector128.Create((byte)0x0F);
		Vector128<sbyte> bound = Vector128.Create((sbyte)(eta is 2 ? 15 : 9));
		Vector256<int> center = Vector256.Create(eta);
		int count = 0;
		int offset = 0;

		for (; offset <= source.Length - sizeof(uint) && count <= destination.Length - Vector256<int>.Count; offset += sizeof(uint))
		{
			Vector128<byte> bytes = Vector128.CreateScalar(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref input, offset))).AsByte();
			Vector128<byte> b = Sse2.UnpackLow(bytes & low, bytes >>> 4);
			uint accepted = Vector128.LessThan(b.AsSByte(), bound).ExtractMostSignificantBits() & 0xFF;
			Vector128<byte> lanes = Vector128.CreateScalarUnsafe(Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref indices, 8 * accepted))).AsByte();
			Vector128<byte> packed = Vector128.ShuffleNative(Vector128.ShuffleNative(remainders, b), lanes);
			(center - Avx2.ConvertToVector256Int32(packed)).StoreUnsafe(ref output, (nuint)count);
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
		Vector256<byte> fields = Vector256.Create(0, 1, 0x80, 0x80, 1, 2, 0x80, 0x80, 2, 3, 0x80, 0x80, 3, 4, 0x80, 0x80, 0, 1, 0x80, 0x80, 1, 2, 0x80, 0x80, 2, 3, 0x80, 0x80, 3, 4, 0x80, 0x80);
		Vector256<uint> shifts = Vector256.Create(0u, 2, 4, 6, 0, 2, 4, 6);

		for (int i = 0; i < 32; ++i)
		{
			(Unpack(ref input, 10 * i, 10, fields, shifts) << D).StoreUnsafe(ref output, (nuint)(8 * i));
		}
	}

	// Each eight values make 13 bytes. 2^12 − t0_i moves to its bit within its first byte, and the bytes of the even and of the odd
	// values of a 128-bit lane, which do not overlap, gather with a shuffle each: those of the low lane into its bytes 0 to 6 and those
	// of the high lane into its bytes 6 to 12, and an or of the lanes joins the halves of byte 6. Groups are stored 16 bytes at a time,
	// the next overwriting the excess, but for the last.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void EncodeT0(ReadOnlySpan<int> t0, Span<byte> destination)
	{
		Debug.Assert(t0.Length is N && destination.Length >= 416);

		ref int source = ref MemoryMarshal.GetReference(t0);
		ref byte target = ref MemoryMarshal.GetReference(destination);
		Vector256<byte> evenFields = Vector256.Create(0, 1, 0x80, 8, 9, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 1, 2, 8, 9, 10, 0x80, 0x80, 0x80, 0x80);
		Vector256<byte> oddFields = Vector256.Create(0x80, 4, 5, 6, 12, 13, 14, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 4, 5, 0x80, 12, 13, 0x80, 0x80, 0x80);
		Vector256<uint> shifts = Vector256.Create(0u, 5, 2, 7, 4, 1, 6, 3);
		Vector256<uint> biases = Vector256.Create(1u << D - 1, 1 << D + 4, 1 << D + 1, 1 << D + 6, 1 << D + 3, 1 << D, 1 << D + 5, 1 << D + 2);

		for (int i = 0; i < 31; ++i)
		{
			Pack13(ref source, shifts, biases, evenFields, oddFields).StoreUnsafe(ref target);
			source = ref Unsafe.Add(ref source, 8);
			target = ref Unsafe.Add(ref target, 13);
		}

		Vector128<byte> last = Pack13(ref source, shifts, biases, evenFields, oddFields);
		Unsafe.WriteUnaligned(ref target, last.AsUInt64().ToScalar());
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref target, 8), last.AsUInt32().GetElement(2));
		Unsafe.Add(ref target, 12) = last.GetElement(12);
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
			Pack3(ref source, ref target);
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
			Vector256<byte> fields = Vector256.Create(0, 0x80, 0x80, 0x80, 0, 0x80, 0x80, 0x80, 0, 1, 0x80, 0x80, 1, 0x80, 0x80, 0x80, 0, 0x80, 0x80, 0x80, 0, 1, 0x80, 0x80, 1, 0x80, 0x80, 0x80, 1, 0x80, 0x80, 0x80);
			return DecodeEta(ref input, ref output, 2, 3, fields, Vector256.Create(0u, 3, 6, 1, 4, 7, 2, 5));
		}
		else
		{
			Vector256<byte> fields = Vector256.Create(0, 0x80, 0x80, 0x80, 0, 0x80, 0x80, 0x80, 1, 0x80, 0x80, 0x80, 1, 0x80, 0x80, 0x80, 0, 0x80, 0x80, 0x80, 0, 0x80, 0x80, 0x80, 1, 0x80, 0x80, 0x80, 1, 0x80, 0x80, 0x80);
			return DecodeEta(ref input, ref output, 4, 4, fields, Vector256.Create(0u, 4, 0, 4, 0, 4, 0, 4));
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
			Vector256<byte> fields = Vector256.Create(0, 1, 2, 0x80, 2, 3, 4, 0x80, 4, 5, 6, 0x80, 6, 7, 8, 0x80, 0, 1, 2, 0x80, 2, 3, 4, 0x80, 4, 5, 6, 0x80, 6, 7, 8, 0x80);
			DecodeZ(ref input, ref output, 18, fields, Vector256.Create(0u, 2, 4, 6, 0, 2, 4, 6));
		}
		else
		{
			Vector256<byte> fields = Vector256.Create(0, 1, 2, 0x80, 2, 3, 4, 0x80, 5, 6, 7, 0x80, 7, 8, 9, 0x80, 0, 1, 2, 0x80, 2, 3, 4, 0x80, 5, 6, 7, 0x80, 7, 8, 9, 0x80);
			DecodeZ(ref input, ref output, 20, fields, Vector256.Create(0u, 4, 0, 4, 0, 4, 0, 4));
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

	// Layers 6 to 8 of NTT on the 16 coefficients of a and b. With x and y the 32-bit interleavings of a and b, lanes i of x and y hold
	// the pairs of layer 7, those of their 128-bit lanes swapped the pairs of layer 6, and those of their interleavings the pairs of
	// layer 8, which interleave once more into the order of a and b.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void NttPair(ref Vector256<int> a, ref Vector256<int> b, ref Vector256<int> zetas)
	{
		Vector256<int> x = Avx2.UnpackLow(a, b);
		Vector256<int> y = Avx2.UnpackHigh(a, b);
		Vector256<int> low = Avx2.Permute2x128(x, y, 0x20);
		Vector256<int> high = Avx2.Permute2x128(x, y, 0x31);
		Butterfly(ref low, ref high, ref zetas);

		x = Avx2.Permute2x128(low, high, 0x20);
		y = Avx2.Permute2x128(low, high, 0x31);
		Butterfly(ref x, ref y, ref Unsafe.Add(ref zetas, 4));

		low = Avx2.UnpackLow(x, y);
		high = Avx2.UnpackHigh(x, y);
		Butterfly(ref low, ref high, ref Unsafe.Add(ref zetas, 8));

		a = Avx2.UnpackLow(low, high);
		b = Avx2.UnpackHigh(low, high);
	}

	// Layers 1 to 3 of NTT⁻¹ on the 16 coefficients of a and b, each shuffle the inverse of one in NttPair.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseNttPair(ref Vector256<int> a, ref Vector256<int> b, ref Vector256<int> zetas)
	{
		Vector256<int> low = Deinterleave(a, b, out Vector256<int> high);
		InverseButterfly(ref low, ref high, ref zetas);

		Vector256<int> x = Deinterleave(low, high, out Vector256<int> y);
		InverseButterfly(ref x, ref y, ref Unsafe.Add(ref zetas, 4));

		low = Avx2.Permute2x128(x, y, 0x20);
		high = Avx2.Permute2x128(x, y, 0x31);
		InverseButterfly(ref low, ref high, ref Unsafe.Add(ref zetas, 8));

		x = Avx2.Permute2x128(low, high, 0x20);
		y = Avx2.Permute2x128(low, high, 0x31);
		a = Deinterleave(x, y, out b);
	}

	// The even 32-bit lanes of each 128-bit lane of a and b, and in odd the odd ones: the inverse of UnpackLow and UnpackHigh.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<int> Deinterleave(Vector256<int> a, Vector256<int> b, out Vector256<int> odd)
	{
		odd = Avx.Shuffle(a.AsSingle(), b.AsSingle(), 0b11_01_11_01).AsInt32();
		return Avx.Shuffle(a.AsSingle(), b.AsSingle(), 0b10_00_10_00).AsInt32();
	}

	// The butterfly of NTT (Algorithm 41) with Zetas[index] in every lane.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Butterfly(ref Vector256<int> low, ref Vector256<int> high, nint index)
	{
		Vector256<int> zeta = Vector256.Create(Unsafe.Add(ref MemoryMarshal.GetReference(MLDsaConstants.Zetas), index));
		Vector256<int> zetaQInverse = Vector256.Create(Unsafe.Add(ref MemoryMarshal.GetReference(MLDsaConstants.ZetasQInverse), index));
		Vector256<int> t = MultiplyMontgomery(high, zeta, zetaQInverse, zeta, zetaQInverse);
		high = low - t;
		low += t;
	}

	// The butterfly of NTT with the four vectors of zetas at zetas.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Butterfly(ref Vector256<int> low, ref Vector256<int> high, ref Vector256<int> zetas)
	{
		Vector256<int> t = MultiplyMontgomery(high, zetas, Unsafe.Add(ref zetas, 1), Unsafe.Add(ref zetas, 2), Unsafe.Add(ref zetas, 3));
		high = low - t;
		low += t;
	}

	// The butterfly of NTT⁻¹ (Algorithm 42), its (low − high) · (−Zetas[index]) taken as (high − low) · Zetas[index].
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseButterfly(ref Vector256<int> low, ref Vector256<int> high, nint index)
	{
		Vector256<int> zeta = Vector256.Create(Unsafe.Add(ref MemoryMarshal.GetReference(MLDsaConstants.Zetas), index));
		Vector256<int> zetaQInverse = Vector256.Create(Unsafe.Add(ref MemoryMarshal.GetReference(MLDsaConstants.ZetasQInverse), index));
		Vector256<int> difference = high - low;
		low += high;
		high = MultiplyMontgomery(difference, zeta, zetaQInverse, zeta, zetaQInverse);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseButterfly(ref Vector256<int> low, ref Vector256<int> high, ref Vector256<int> zetas)
	{
		Vector256<int> difference = high - low;
		low += high;
		high = MultiplyMontgomery(difference, zetas, Unsafe.Add(ref zetas, 1), Unsafe.Add(ref zetas, 2), Unsafe.Add(ref zetas, 3));
	}

	// Layer 8 of NTT⁻¹ with the factor that ends it.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LastInverseButterfly(ref Vector256<int> low, ref Vector256<int> high)
	{
		Vector256<int> factor = Vector256.Create(MLDsaConstants.InverseNttFactor);
		Vector256<int> factorQInverse = Vector256.Create(MLDsaConstants.InverseNttFactorQInverse);
		Vector256<int> zeta = Vector256.Create(MLDsaConstants.LastInverseZeta);
		Vector256<int> zetaQInverse = Vector256.Create(MLDsaConstants.LastInverseZetaQInverse);
		Vector256<int> difference = high - low;
		low = MultiplyMontgomery(low + high, factor, factorQInverse, factor, factorQInverse);
		high = MultiplyMontgomery(difference, zeta, zetaQInverse, zeta, zetaQInverse);
	}

	// a · ζ · R⁻¹ mod q in (−q, q) for |ζ| < q / 2: ζ of the even lanes in the even lanes of zeta, ζ of the odd lanes in the even lanes of
	// zetaOdd, each with its ζ · q⁻¹ mod 2^32. The 64-bit differences have zero low halves, so their high halves join with an or.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<int> MultiplyMontgomery(Vector256<int> a, Vector256<int> zeta, Vector256<int> zetaQInverse, Vector256<int> zetaOdd, Vector256<int> zetaOddQInverse)
	{
		Vector256<int> q = Vector256.Create(Q);
		Vector256<int> aOdd = Odd(a);
		Vector256<long> even = Avx2.Multiply(a, zeta) - Avx2.Multiply(Avx2.Multiply(a, zetaQInverse).AsInt32(), q);
		Vector256<long> odd = Avx2.Multiply(aOdd, zetaOdd) - Avx2.Multiply(Avx2.Multiply(aOdd, zetaOddQInverse).AsInt32(), q);
		return (even.AsUInt64() >>> 32).AsInt32() | odd.AsInt32();
	}

	// R⁻¹ · c mod q in (−q, q) for |c| < 2^31 · q, with c of the even lanes in even and of the odd lanes in odd.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<int> MontgomeryReduce(Vector256<long> even, Vector256<long> odd)
	{
		Vector256<int> q = Vector256.Create(Q);
		Vector256<int> qInverse = Vector256.Create(MLDsaConstants.QInverse);
		even -= Avx2.Multiply(Avx2.Multiply(even.AsInt32(), qInverse).AsInt32(), q);
		odd -= Avx2.Multiply(Avx2.Multiply(odd.AsInt32(), qInverse).AsInt32(), q);
		return (even.AsUInt64() >>> 32).AsInt32() | odd.AsInt32();
	}

	// The odd lanes moved down into the even lanes, which vpmuldq reads.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<int> Odd(Vector256<int> a)
	{
		return (a.AsInt64() >>> 32).AsInt32();
	}

	// MLDsaScalar.Reduce32 in every lane.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<int> Reduce(Vector256<int> a)
	{
		Vector256<int> quotient = a + Vector256.Create(1 << 22) >> 23;
		return a - quotient * Vector256.Create(Q);
	}

	// Maps (−q, q) to [0, q).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<int> ToCanonical(Vector256<int> a)
	{
		return a + (a >> 31 & Vector256.Create(Q));
	}

	// MLDsaScalar.Decompose in every lane.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<int> Decompose(Vector256<int> r, int gamma2, out Vector256<int> r0)
	{
		Vector256<int> a = ToCanonical(r);
		Vector256<int> a1 = a + Vector256.Create(127) >> 7;

		if (gamma2 is MLDsaConstants.Gamma2Large)
		{
			a1 = a1 * Vector256.Create(1025) + Vector256.Create(1 << 21) >> 22 & Vector256.Create(15);
		}
		else
		{
			a1 = a1 * Vector256.Create(11275) + Vector256.Create(1 << 23) >> 24;
			a1 ^= Vector256.Create(43) - a1 >> 31 & a1;
		}

		r0 = a - a1 * Vector256.Create(2 * gamma2);
		r0 -= Vector256.Create((Q - 1) / 2) - r0 >> 31 & Vector256.Create(Q);
		return a1;
	}

	// The eight values of bits bits from bits bytes at start of the 32 · bits at source. Lane h takes values 4h to 4h + 3 from the 16
	// bytes at byte 4h · bits / 8, moved back to end with the source where they would pass it: fields picks the bytes of each value
	// into its 32-bit lane, and shifts moves it down.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<int> Unpack(ref byte source, int start, [ConstantExpected(Min = 3, Max = 20)] int bits, Vector256<byte> fields, Vector256<uint> shifts)
	{
		int last = 32 * bits - 16;
		int split = start + bits / 2;
		int first = Math.Min(start, last);
		int second = Math.Min(split, last);
		Vector256<byte> window = Vector256.Create(Vector128.LoadUnsafe(ref source, (nuint)first), Vector128.LoadUnsafe(ref source, (nuint)second));
		Vector256<byte> moved = Vector256.Create(Vector128.Create((byte)(start - first)), Vector128.Create((byte)(split - second)));
		Vector256<uint> values = Avx2.ShiftRightLogicalVariable(Avx2.Shuffle(window, fields + moved).AsUInt32(), shifts);
		return (values & Vector256.Create((1u << bits) - 1)).AsInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool DecodeEta(ref byte source, ref int destination, [ConstantExpected] int eta, [ConstantExpected(Min = 3, Max = 4)] int bits, Vector256<byte> fields, Vector256<uint> shifts)
	{
		Vector256<int> inRange = Vector256<int>.Zero;

		for (int i = 0; i < 32; ++i)
		{
			Vector256<int> v = Unpack(ref source, bits * i, bits, fields, shifts);
			inRange |= Vector256.Create(2 * eta) - v;
			(Vector256.Create(eta) - v).StoreUnsafe(ref destination, (nuint)(8 * i));
		}

		return inRange.ExtractMostSignificantBits() is 0;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void DecodeZ(ref byte source, ref int destination, [ConstantExpected(Min = 18, Max = 20)] int bits, Vector256<byte> fields, Vector256<uint> shifts)
	{
		for (int i = 0; i < 32; ++i)
		{
			(Vector256.Create(1 << bits - 1) - Unpack(ref source, bits * i, bits, fields, shifts)).StoreUnsafe(ref destination, (nuint)(8 * i));
		}
	}

	// Values of bits bits, bits even and at least 10: bias − f_i, or f_i without subtract. Each value moves to its bit within its
	// first byte, and the bytes of the even and of the odd values of a 128-bit lane, which do not overlap, gather with a shuffle
	// each into bits / 2 bytes. Lanes are stored 16 bytes at a time, the next overwriting the excess, but for those near the end.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PackWide(ref int source, ref byte destination, [ConstantExpected(Min = 10, Max = 20)] int bits, int bias, bool subtract)
	{
		Vector256<byte> evenFields;
		Vector256<byte> oddFields;
		Vector256<uint> shifts;

		switch (bits)
		{
			case 10:
			{
				evenFields = Vector256.Create(Vector128.Create(0, 1, 8, 9, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80));
				oddFields = Vector256.Create(Vector128.Create(0x80, 4, 5, 12, 13, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80));
				shifts = Vector256.Create(0u, 2, 4, 6, 0, 2, 4, 6);
				break;
			}
			case 18:
			{
				evenFields = Vector256.Create(Vector128.Create(0, 1, 2, 0x80, 8, 9, 10, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80));
				oddFields = Vector256.Create(Vector128.Create(0x80, 0x80, 4, 5, 6, 0x80, 12, 13, 14, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80));
				shifts = Vector256.Create(0u, 2, 4, 6, 0, 2, 4, 6);
				break;
			}
			default:
			{
				evenFields = Vector256.Create(Vector128.Create(0, 1, 2, 0x80, 0x80, 8, 9, 10, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80));
				oddFields = Vector256.Create(Vector128.Create(0x80, 0x80, 4, 5, 6, 0x80, 0x80, 12, 13, 14, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80));
				shifts = Vector256.Create(0u, 4, 0, 4, 0, 4, 0, 4);
				break;
			}
		}

		for (int i = 0; i < 32; ++i)
		{
			Vector256<int> values = Vector256.LoadUnsafe(ref source, (nuint)(8 * i));

			if (subtract)
			{
				values = Vector256.Create(bias) - values;
			}

			Vector256<byte> shifted = Avx2.ShiftLeftLogicalVariable(values.AsUInt32(), shifts).AsByte();
			Vector256<byte> packed = Avx2.Shuffle(shifted, evenFields) | Avx2.Shuffle(shifted, oddFields);
			StoreLane(packed.GetLower(), ref destination, bits * i, bits);
			StoreLane(packed.GetUpper(), ref destination, bits * i + bits / 2, bits);
		}
	}

	// The bits / 2 bytes at the start of lane at offset, as a store of 16 bytes where that stays within the 32 · bits.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreLane(Vector128<byte> lane, ref byte destination, int offset, [ConstantExpected(Min = 10, Max = 20)] int bits)
	{
		if (offset <= 32 * bits - 16)
		{
			lane.StoreUnsafe(ref destination, (nuint)offset);
			return;
		}

		ref byte target = ref Unsafe.Add(ref destination, offset);

		if (bits is 10)
		{
			Unsafe.WriteUnaligned(ref target, lane.AsUInt32().ToScalar());
			Unsafe.Add(ref target, 4) = lane.GetElement(4);
		}
		else
		{
			Unsafe.WriteUnaligned(ref target, lane.AsUInt64().ToScalar());

			if (bits is 18)
			{
				Unsafe.Add(ref target, 8) = lane.GetElement(8);
			}
			else
			{
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref target, 8), lane.AsUInt16().GetElement(4));
			}
		}
	}

	// The 13 bytes of the eight values at source, 2^12 − t0_i each, at the start of a 128-bit vector. The value shifted to its bit is
	// biases, 2^12 shifted alike, less the shifted t0_i.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> Pack13(ref int source, Vector256<uint> shifts, Vector256<uint> biases, Vector256<byte> evenFields, Vector256<byte> oddFields)
	{
		Vector256<byte> shifted = (biases - Avx2.ShiftLeftLogicalVariable(Vector256.LoadUnsafe(ref source).AsUInt32(), shifts)).AsByte();
		Vector256<byte> packed = Avx2.Shuffle(shifted, evenFields) | Avx2.Shuffle(shifted, oddFields);
		return packed.GetUpper() | packed.GetLower();
	}

	// The 32 values at source in order as bytes, bias − f_i or f_i without subtract, each below 256.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> LoadBytes(ref int source, int bias, bool subtract)
	{
		Vector256<int> v0 = Vector256.LoadUnsafe(ref source);
		Vector256<int> v1 = Vector256.LoadUnsafe(ref source, 8);
		Vector256<int> v2 = Vector256.LoadUnsafe(ref source, 16);
		Vector256<int> v3 = Vector256.LoadUnsafe(ref source, 24);

		if (subtract)
		{
			Vector256<int> b = Vector256.Create(bias);
			v0 = b - v0;
			v1 = b - v1;
			v2 = b - v2;
			v3 = b - v3;
		}

		Vector256<byte> bytes = Avx2.PackUnsignedSaturate(Avx2.PackSignedSaturate(v0, v1), Avx2.PackSignedSaturate(v2, v3));
		return Avx2.PermuteVar8x32(bytes.AsInt32(), Vector256.Create(0, 4, 1, 5, 2, 6, 3, 7)).AsByte();
	}

	// Each 32 values below 8 make 12 bytes: pairs join into 6 bits, fours into 12 and eights into the three low bytes of each 64-bit
	// lane, which a shuffle gathers into the first 6 bytes of the low 128-bit lane and the next 6 of the high one.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Pack3(ref int source, ref byte destination)
	{
		Vector256<byte> fields = Vector256.Create(0, 1, 2, 8, 9, 10, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 1, 2, 8, 9, 10, 0x80, 0x80, 0x80, 0x80);

		for (nuint i = 0; i < 8; ++i)
		{
			Vector256<short> pairs = Avx2.MultiplyAddAdjacent(LoadBytes(ref Unsafe.Add(ref source, 32 * i), 2, true), Vector256.Create((short)(1 | 8 << 8)).AsSByte());
			Vector256<ulong> fours = Avx2.MultiplyAddAdjacent(pairs, Vector256.Create(1 | 64 << 16).AsInt16()).AsUInt64();
			Vector256<byte> lanes = Avx2.Shuffle((fours | fours >>> 20).AsByte(), fields);
			Vector128<byte> packed = lanes.GetLower() | lanes.GetUpper();

			if (i < 7)
			{
				packed.StoreUnsafe(ref destination, 12 * i);
			}
			else
			{
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 84), packed.AsUInt64().ToScalar());
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 92), packed.AsUInt32().GetElement(2));
			}
		}
	}

	// Each 32 values below 16 make 16 bytes, a pair per byte.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Pack4(ref int source, ref byte destination, int bias, bool subtract)
	{
		for (nuint i = 0; i < 8; ++i)
		{
			Vector256<short> pairs = Avx2.MultiplyAddAdjacent(LoadBytes(ref Unsafe.Add(ref source, 32 * i), bias, subtract), Vector256.Create((short)(1 | 16 << 8)).AsSByte());
			Vector256<ulong> packed = Avx2.PackUnsignedSaturate(pairs, pairs).AsUInt64();
			Avx2.Permute4x64(packed, 0b11_01_10_00).AsByte().GetLower().StoreUnsafe(ref destination, 16 * i);
		}
	}

	// Each 32 values below 64 make 24 bytes: pairs join into 12 bits and fours into the three low bytes of each 32-bit lane,
	// which a shuffle and a permutation gather.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Pack6(ref int source, ref byte destination)
	{
		Vector256<byte> fields = Vector256.Create(Vector128.Create(0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 0x80, 0x80, 0x80, 0x80));
		Vector256<int> order = Vector256.Create(0, 1, 2, 4, 5, 6, 3, 7);

		for (nuint i = 0; i < 8; ++i)
		{
			Vector256<short> pairs = Avx2.MultiplyAddAdjacent(LoadBytes(ref Unsafe.Add(ref source, 32 * i), 0, false), Vector256.Create((short)(1 | 64 << 8)).AsSByte());
			Vector256<int> fours = Avx2.MultiplyAddAdjacent(pairs, Vector256.Create(1 | 4096 << 16).AsInt16());
			Vector256<byte> packed = Avx2.PermuteVar8x32(Avx2.Shuffle(fours.AsByte(), fields).AsInt32(), order).AsByte();

			if (i < 7)
			{
				packed.StoreUnsafe(ref destination, 24 * i);
			}
			else
			{
				packed.GetLower().StoreUnsafe(ref destination, 168);
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 184), packed.GetUpper().AsUInt64().ToScalar());
			}
		}
	}
}
