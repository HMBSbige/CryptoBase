using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Kems.MLKem;

// Eight coefficients per 128-bit vector, one implementation for SSE4.1 and AdvSimd. Products with a constant ζ use Barrett multiplication, which needs only the rounding high multiplication both have, so the constants are plain residues.
internal readonly partial struct MLKemVector128 : IMLKemKernel
{
	private const int N = MLKemConstants.N;
	private const short Q = MLKemConstants.Q;

	// R mod q = 2285 ≡ −1044 and ⌊−1044 · 2^15 / q⌉.
	private const short RModQ = -1044;
	private const short RModQQuotient = -10276;

	private const byte Zero = 0xFF;

	public static bool IsSupported => Sse41.IsSupported || AdvSimd.Arm64.IsSupported;

	// Layers 1 to 3 run on vectors 32 coefficients apart, layers 4 to 7 on four consecutive ones, which Interleave pairs for layers 6 and 7 and, applied a third time, restores. Coefficients stay below 8q < 2^15 until the final reduction.
	public static void Ntt(Span<short> f)
	{
		Debug.Assert(f.Length is N);

		ref short coefficients = ref MemoryMarshal.GetReference(f);
		ref short zetas = ref MemoryMarshal.GetReference(NttZetas);

		for (nuint offset = 0; offset < 32; offset += 8)
		{
			ref short p = ref Unsafe.Add(ref coefficients, offset);
			Vector128<short> f0 = Vector128.LoadUnsafe(ref p);
			Vector128<short> f1 = Vector128.LoadUnsafe(ref p, 32);
			Vector128<short> f2 = Vector128.LoadUnsafe(ref p, 64);
			Vector128<short> f3 = Vector128.LoadUnsafe(ref p, 96);
			Vector128<short> f4 = Vector128.LoadUnsafe(ref p, 128);
			Vector128<short> f5 = Vector128.LoadUnsafe(ref p, 160);
			Vector128<short> f6 = Vector128.LoadUnsafe(ref p, 192);
			Vector128<short> f7 = Vector128.LoadUnsafe(ref p, 224);
			Butterfly(ref f0, ref f4, ref zetas);
			Butterfly(ref f1, ref f5, ref zetas);
			Butterfly(ref f2, ref f6, ref zetas);
			Butterfly(ref f3, ref f7, ref zetas);
			Butterfly(ref f0, ref f2, ref Unsafe.Add(ref zetas, 16));
			Butterfly(ref f1, ref f3, ref Unsafe.Add(ref zetas, 16));
			Butterfly(ref f4, ref f6, ref Unsafe.Add(ref zetas, 32));
			Butterfly(ref f5, ref f7, ref Unsafe.Add(ref zetas, 32));
			Butterfly(ref f0, ref f1, ref Unsafe.Add(ref zetas, 48));
			Butterfly(ref f2, ref f3, ref Unsafe.Add(ref zetas, 64));
			Butterfly(ref f4, ref f5, ref Unsafe.Add(ref zetas, 80));
			Butterfly(ref f6, ref f7, ref Unsafe.Add(ref zetas, 96));
			f0.StoreUnsafe(ref p);
			f1.StoreUnsafe(ref p, 32);
			f2.StoreUnsafe(ref p, 64);
			f3.StoreUnsafe(ref p, 96);
			f4.StoreUnsafe(ref p, 128);
			f5.StoreUnsafe(ref p, 160);
			f6.StoreUnsafe(ref p, 192);
			f7.StoreUnsafe(ref p, 224);
		}

		for (nuint offset = 0; offset < N; offset += 32)
		{
			zetas = ref Unsafe.Add(ref zetas, 7 * 16);
			ref short p = ref Unsafe.Add(ref coefficients, offset);
			Vector128<short> f0 = Vector128.LoadUnsafe(ref p);
			Vector128<short> f1 = Vector128.LoadUnsafe(ref p, 8);
			Vector128<short> f2 = Vector128.LoadUnsafe(ref p, 16);
			Vector128<short> f3 = Vector128.LoadUnsafe(ref p, 24);
			Butterfly(ref f0, ref f2, ref zetas);
			Butterfly(ref f1, ref f3, ref zetas);
			Butterfly(ref f0, ref f1, ref Unsafe.Add(ref zetas, 16));
			Butterfly(ref f2, ref f3, ref Unsafe.Add(ref zetas, 32));
			Interleave(ref f0, ref f1);
			Interleave(ref f2, ref f3);
			Butterfly(ref f0, ref f1, ref Unsafe.Add(ref zetas, 48));
			Butterfly(ref f2, ref f3, ref Unsafe.Add(ref zetas, 64));
			Interleave(ref f0, ref f1);
			Interleave(ref f2, ref f3);
			Butterfly(ref f0, ref f1, ref Unsafe.Add(ref zetas, 80));
			Butterfly(ref f2, ref f3, ref Unsafe.Add(ref zetas, 96));
			f0 = BarrettReduce(f0);
			f1 = BarrettReduce(f1);
			f2 = BarrettReduce(f2);
			f3 = BarrettReduce(f3);
			Interleave(ref f0, ref f1);
			Interleave(ref f2, ref f3);
			f0.StoreUnsafe(ref p);
			f1.StoreUnsafe(ref p, 8);
			f2.StoreUnsafe(ref p, 16);
			f3.StoreUnsafe(ref p, 24);
		}
	}

	// The layers of Ntt in reverse. The sums are reduced in layers 3 and 6 before they reach 8q.
	public static void InverseNtt(Span<short> f)
	{
		Debug.Assert(f.Length is N);

		ref short coefficients = ref MemoryMarshal.GetReference(f);
		ref short zetas = ref MemoryMarshal.GetReference(InverseNttZetas);

		for (nuint offset = 0; offset < N; offset += 32)
		{
			ref short p = ref Unsafe.Add(ref coefficients, offset);
			Vector128<short> f0 = Vector128.LoadUnsafe(ref p);
			Vector128<short> f1 = Vector128.LoadUnsafe(ref p, 8);
			Vector128<short> f2 = Vector128.LoadUnsafe(ref p, 16);
			Vector128<short> f3 = Vector128.LoadUnsafe(ref p, 24);
			Deinterleave(ref f0, ref f1);
			Deinterleave(ref f2, ref f3);
			InverseButterfly(ref f0, ref f1, ref zetas);
			InverseButterfly(ref f2, ref f3, ref Unsafe.Add(ref zetas, 16));
			Deinterleave(ref f0, ref f1);
			Deinterleave(ref f2, ref f3);
			InverseButterfly(ref f0, ref f1, ref Unsafe.Add(ref zetas, 32));
			InverseButterfly(ref f2, ref f3, ref Unsafe.Add(ref zetas, 48));
			Deinterleave(ref f0, ref f1);
			Deinterleave(ref f2, ref f3);
			InverseButterflyReduced(ref f0, ref f1, ref Unsafe.Add(ref zetas, 64));
			InverseButterflyReduced(ref f2, ref f3, ref Unsafe.Add(ref zetas, 80));
			InverseButterfly(ref f0, ref f2, ref Unsafe.Add(ref zetas, 96));
			InverseButterfly(ref f1, ref f3, ref Unsafe.Add(ref zetas, 96));
			f0.StoreUnsafe(ref p);
			f1.StoreUnsafe(ref p, 8);
			f2.StoreUnsafe(ref p, 16);
			f3.StoreUnsafe(ref p, 24);
			zetas = ref Unsafe.Add(ref zetas, 7 * 16);
		}

		for (nuint offset = 0; offset < 32; offset += 8)
		{
			ref short p = ref Unsafe.Add(ref coefficients, offset);
			Vector128<short> f0 = Vector128.LoadUnsafe(ref p);
			Vector128<short> f1 = Vector128.LoadUnsafe(ref p, 32);
			Vector128<short> f2 = Vector128.LoadUnsafe(ref p, 64);
			Vector128<short> f3 = Vector128.LoadUnsafe(ref p, 96);
			Vector128<short> f4 = Vector128.LoadUnsafe(ref p, 128);
			Vector128<short> f5 = Vector128.LoadUnsafe(ref p, 160);
			Vector128<short> f6 = Vector128.LoadUnsafe(ref p, 192);
			Vector128<short> f7 = Vector128.LoadUnsafe(ref p, 224);
			InverseButterfly(ref f0, ref f1, ref zetas);
			InverseButterfly(ref f2, ref f3, ref Unsafe.Add(ref zetas, 16));
			InverseButterfly(ref f4, ref f5, ref Unsafe.Add(ref zetas, 32));
			InverseButterfly(ref f6, ref f7, ref Unsafe.Add(ref zetas, 48));
			InverseButterflyReduced(ref f0, ref f2, ref Unsafe.Add(ref zetas, 64));
			InverseButterflyReduced(ref f1, ref f3, ref Unsafe.Add(ref zetas, 64));
			InverseButterflyReduced(ref f4, ref f6, ref Unsafe.Add(ref zetas, 80));
			InverseButterflyReduced(ref f5, ref f7, ref Unsafe.Add(ref zetas, 80));
			LastInverseButterfly(ref f0, ref f4, ref Unsafe.Add(ref zetas, 96));
			LastInverseButterfly(ref f1, ref f5, ref Unsafe.Add(ref zetas, 96));
			LastInverseButterfly(ref f2, ref f6, ref Unsafe.Add(ref zetas, 96));
			LastInverseButterfly(ref f3, ref f7, ref Unsafe.Add(ref zetas, 96));
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

	// The product of a pair is a' · (b0, b1) and a · (b1, b0) with a' = (a0, ±γ · a1). Each is below 2q², so the sums of up to four stay below q · 2^15, the input bound of MontgomeryReduce.
	public static void MultiplyAccumulate(ReadOnlySpan<short> a, int aStride, ReadOnlySpan<short> b, Span<short> destination, int count)
	{
		Debug.Assert(count is >= 1 and <= 4);
		Debug.Assert(aStride >= N && a.Length >= (count - 1) * aStride + N && b.Length >= count * N && destination.Length is N);

		ref short x = ref MemoryMarshal.GetReference(a);
		ref short y = ref MemoryMarshal.GetReference(b);
		ref short z = ref MemoryMarshal.GetReference(destination);
		ref short gammas = ref MemoryMarshal.GetReference(BaseMultiplyGammas);
		nuint stride = (nuint)aStride;
		nuint end = (nuint)count * N;

		for (nuint i = 0; i < N; i += 8)
		{
			Vector128<short> gamma = Vector128.LoadUnsafe(ref gammas, 2 * i);
			Vector128<short> gammaQuotient = Vector128.LoadUnsafe(ref gammas, 2 * i + 8);
			Vector128<int> even;
			Vector128<int> odd;

			if (Sse2.IsSupported)
			{
				even = Vector128<int>.Zero;
				odd = Vector128<int>.Zero;

				for (nuint j = i, k = i; j < end; j += N, k += stride)
				{
					Vector128<short> u = Vector128.LoadUnsafe(ref x, k);
					Vector128<short> v = Vector128.LoadUnsafe(ref y, j);
					even += Sse2.MultiplyAddAdjacent(MultiplyConstant(u, gamma, gammaQuotient), v);
					odd += Sse2.MultiplyAddAdjacent(u, Vector128.Shuffle(v, Vector128.Create(1, 0, 3, 2, 5, 4, 7, 6)));
				}
			}
			else
			{
				Vector128<int> evenLow = Vector128<int>.Zero;
				Vector128<int> evenHigh = Vector128<int>.Zero;
				Vector128<int> oddLow = Vector128<int>.Zero;
				Vector128<int> oddHigh = Vector128<int>.Zero;

				for (nuint j = i, k = i; j < end; j += N, k += stride)
				{
					Vector128<short> u = Vector128.LoadUnsafe(ref x, k);
					Vector128<short> v = Vector128.LoadUnsafe(ref y, j);
					Vector128<short> w = MultiplyConstant(u, gamma, gammaQuotient);
					Vector128<short> swapped = AdvSimd.ReverseElement16(v.AsInt32()).AsInt16();
					evenHigh = AdvSimd.MultiplyWideningUpperAndAdd(evenHigh, w, v);
					evenLow = AdvSimd.MultiplyWideningLowerAndAdd(evenLow, w.GetLower(), v.GetLower());
					oddHigh = AdvSimd.MultiplyWideningUpperAndAdd(oddHigh, u, swapped);
					oddLow = AdvSimd.MultiplyWideningLowerAndAdd(oddLow, u.GetLower(), swapped.GetLower());
				}

				even = AdvSimd.Arm64.AddPairwise(evenLow, evenHigh);
				odd = AdvSimd.Arm64.AddPairwise(oddLow, oddHigh);
			}

			MontgomeryReduce(even, odd).StoreUnsafe(ref z, i);
		}
	}

	public static void Reduce(Span<short> f)
	{
		Debug.Assert(f.Length is N);

		ref short coefficients = ref MemoryMarshal.GetReference(f);

		for (nuint i = 0; i < N; i += 8)
		{
			BarrettReduce(Vector128.LoadUnsafe(ref coefficients, i)).StoreUnsafe(ref coefficients, i);
		}
	}

	public static void ToMontgomery(Span<short> f)
	{
		Debug.Assert(f.Length is N);

		ref short coefficients = ref MemoryMarshal.GetReference(f);
		Vector128<short> factor = Vector128.Create(RModQ);
		Vector128<short> quotient = Vector128.Create(RModQQuotient);

		for (nuint i = 0; i < N; i += 8)
		{
			MultiplyConstant(Vector128.LoadUnsafe(ref coefficients, i), factor, quotient).StoreUnsafe(ref coefficients, i);
		}
	}

	public static void Add(ReadOnlySpan<short> left, ReadOnlySpan<short> right, Span<short> destination)
	{
		Debug.Assert(left.Length is N && right.Length is N && destination.Length is N);

		ref short x = ref MemoryMarshal.GetReference(left);
		ref short y = ref MemoryMarshal.GetReference(right);
		ref short z = ref MemoryMarshal.GetReference(destination);

		for (nuint i = 0; i < N; i += 8)
		{
			(Vector128.LoadUnsafe(ref x, i) + Vector128.LoadUnsafe(ref y, i)).StoreUnsafe(ref z, i);
		}
	}

	public static void Subtract(ReadOnlySpan<short> left, ReadOnlySpan<short> right, Span<short> destination)
	{
		Debug.Assert(left.Length is N && right.Length is N && destination.Length is N);

		ref short x = ref MemoryMarshal.GetReference(left);
		ref short y = ref MemoryMarshal.GetReference(right);
		ref short z = ref MemoryMarshal.GetReference(destination);

		for (nuint i = 0; i < N; i += 8)
		{
			(Vector128.LoadUnsafe(ref x, i) - Vector128.LoadUnsafe(ref y, i)).StoreUnsafe(ref z, i);
		}
	}

	// Four vectors make three: each 32-bit lane of Pack12 holds the three bytes of a pair of coefficients.
	public static void Encode12(ReadOnlySpan<short> f, Span<byte> destination)
	{
		Debug.Assert(f.Length is N && destination.Length >= 384);

		ref short x = ref MemoryMarshal.GetReference(f);
		ref byte y = ref MemoryMarshal.GetReference(destination);

		for (nuint i = 0, offset = 0; i < N; i += 32, offset += 48)
		{
			Vector128<byte> w0 = Pack12(Vector128.LoadUnsafe(ref x, i));
			Vector128<byte> w1 = Pack12(Vector128.LoadUnsafe(ref x, i + 8));
			Vector128<byte> w2 = Pack12(Vector128.LoadUnsafe(ref x, i + 16));
			Vector128<byte> w3 = Pack12(Vector128.LoadUnsafe(ref x, i + 24));
			Vector128<byte> o0 = Vector128.Shuffle(w0, Vector128.Create(0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, Zero, Zero, Zero, Zero))
				| Vector128.Shuffle(w1, Vector128.Create(Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero, 0, 1, 2, 4));
			Vector128<byte> o1 = Vector128.Shuffle(w1, Vector128.Create(5, 6, 8, 9, 10, 12, 13, 14, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero))
				| Vector128.Shuffle(w2, Vector128.Create(Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero, 0, 1, 2, 4, 5, 6, 8, 9));
			Vector128<byte> o2 = Vector128.Shuffle(w2, Vector128.Create(10, 12, 13, 14, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero))
				| Vector128.Shuffle(w3, Vector128.Create(Zero, Zero, Zero, Zero, 0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14));
			o0.StoreUnsafe(ref y, offset);
			o1.StoreUnsafe(ref y, offset + 16);
			o2.StoreUnsafe(ref y, offset + 32);
		}
	}

	// The check takes the maximum of every value rather than branch.
	public static bool Decode12(ReadOnlySpan<byte> source, Span<short> f)
	{
		Debug.Assert(source.Length >= 384 && f.Length is N);

		ref byte x = ref MemoryMarshal.GetReference(source);
		ref short y = ref MemoryMarshal.GetReference(f);
		Vector128<short> maximum = Vector128<short>.Zero;

		for (nuint i = 0, offset = 0; i < N; i += 32, offset += 48)
		{
			Vector128<byte> b0 = Vector128.LoadUnsafe(ref x, offset);
			Vector128<byte> b1 = Vector128.LoadUnsafe(ref x, offset + 16);
			Vector128<byte> b2 = Vector128.LoadUnsafe(ref x, offset + 32);
			Vector128<short> c0 = Unpack12(b0, 0);
			Vector128<short> c1 = Unpack12(AlignRight(b1, b0, 12), 0);
			Vector128<short> c2 = Unpack12(AlignRight(b2, b1, 8), 0);
			Vector128<short> c3 = Unpack12(b2, 4);
			maximum = Vector128.Max(maximum, Vector128.Max(Vector128.Max(c0, c1), Vector128.Max(c2, c3)));
			c0.StoreUnsafe(ref y, i);
			c1.StoreUnsafe(ref y, i + 8);
			c2.StoreUnsafe(ref y, i + 16);
			c3.StoreUnsafe(ref y, i + 24);
		}

		return Vector128.LessThanAll(maximum, Vector128.Create(Q));
	}

	public static void Compress(ReadOnlySpan<short> f, Span<byte> destination, int bits)
	{
		Debug.Assert(bits is 1 or 4 or 5 or 10 or 11);
		Debug.Assert(f.Length is N && destination.Length >= 32 * bits);

		ref short x = ref MemoryMarshal.GetReference(f);
		ref byte y = ref MemoryMarshal.GetReference(destination);

		switch (bits)
		{
			case 1:
			{
				Compress1(ref x, ref y);
				break;
			}
			case 4:
			{
				Compress4(ref x, ref y);
				break;
			}
			case 5:
			{
				Compress5(ref x, ref y);
				break;
			}
			case 10:
			{
				Compress10(ref x, ref y);
				break;
			}
			default:
			{
				Compress11(ref x, ref y);
				break;
			}
		}
	}

	public static void Decompress(ReadOnlySpan<byte> source, Span<short> f, int bits)
	{
		Debug.Assert(bits is 1 or 4 or 5 or 10 or 11);
		Debug.Assert(source.Length >= 32 * bits && f.Length is N);

		ref byte x = ref MemoryMarshal.GetReference(source);
		ref short y = ref MemoryMarshal.GetReference(f);

		switch (bits)
		{
			case 1:
			{
				Decompress(ref x, ref y, 1);
				break;
			}
			case 4:
			{
				Decompress(ref x, ref y, 4);
				break;
			}
			case 5:
			{
				Decompress(ref x, ref y, 5);
				break;
			}
			case 10:
			{
				Decompress(ref x, ref y, 10);
				break;
			}
			default:
			{
				Decompress(ref x, ref y, 11);
				break;
			}
		}
	}

	// Nothing is written past the returned count. The bytes are public, so the shuffle may depend on them.
	[SkipLocalsInit]
	public static int RejectSample(ReadOnlySpan<byte> source, Span<short> destination)
	{
		Debug.Assert(source.Length % 3 is 0);

		ref byte x = ref MemoryMarshal.GetReference(source);
		ref byte shuffles = ref MemoryMarshal.GetReference(RejectShuffles);
		Span<short> buffer = stackalloc short[N + 8];
		ref short y = ref MemoryMarshal.GetReference(buffer);
		nuint length = (nuint)source.Length;
		nuint capacity = (nuint)destination.Length;
		nuint i = 0;
		nuint sampled = 0;

		for (; sampled < capacity && sampled <= N && i + 16 <= length; i += 12)
		{
			Vector128<short> candidates = Unpack12(Vector128.LoadUnsafe(ref x, i), 0);
			uint accepted = ExtractMask(Vector128.LessThan(candidates, Vector128.Create(Q)), out uint acceptedCount);
			Vector128<byte> shuffle = Vector128.LoadUnsafe(ref shuffles, 16 * (nuint)accepted);
			Vector128.ShuffleNative(candidates.AsByte(), shuffle).AsInt16().StoreUnsafe(ref y, sampled);
			sampled += acceptedCount;
		}

		int count = (int)Math.Min(sampled, capacity);
		buffer.Slice(0, count).CopyTo(destination);
		return count + MLKemScalar.RejectSample(source.Slice((int)i), destination.Slice(count));
	}

	public static void SampleCbd(ReadOnlySpan<byte> source, Span<short> f, int eta)
	{
		Debug.Assert(eta is 2 or 3);
		Debug.Assert(source.Length >= 64 * eta && f.Length is N);

		ref byte x = ref MemoryMarshal.GetReference(source);
		ref short y = ref MemoryMarshal.GetReference(f);

		if (eta is 2)
		{
			SampleCbd2(ref x, ref y);
		}
		else
		{
			SampleCbd3(ref x, ref y);
		}
	}

	// The butterfly of NTT (Algorithm 9) with ζ and ζ' at zeta and zeta + 8.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Butterfly(ref Vector128<short> low, ref Vector128<short> high, ref short zeta)
	{
		Vector128<short> t = MultiplyConstant(high, Vector128.LoadUnsafe(ref zeta), Vector128.LoadUnsafe(ref zeta, 8));
		high = low - t;
		low += t;
	}

	// The butterfly of NTT⁻¹ (Algorithm 10).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseButterfly(ref Vector128<short> low, ref Vector128<short> high, ref short zeta)
	{
		Vector128<short> difference = high - low;
		low += high;
		high = MultiplyConstant(difference, Vector128.LoadUnsafe(ref zeta), Vector128.LoadUnsafe(ref zeta, 8));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseButterflyReduced(ref Vector128<short> low, ref Vector128<short> high, ref short zeta)
	{
		Vector128<short> difference = high - low;
		low = BarrettReduce(low + high);
		high = MultiplyConstant(difference, Vector128.LoadUnsafe(ref zeta), Vector128.LoadUnsafe(ref zeta, 8));
	}

	// The last layer of NTT⁻¹ also multiplies the sum by 2^9 and the difference by ζ · 2^9.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LastInverseButterfly(ref Vector128<short> low, ref Vector128<short> high, ref short factors)
	{
		Vector128<short> difference = high - low;
		low = MultiplyConstant(low + high, Vector128.LoadUnsafe(ref factors), Vector128.LoadUnsafe(ref factors, 8));
		high = MultiplyConstant(difference, Vector128.LoadUnsafe(ref factors, 16), Vector128.LoadUnsafe(ref factors, 24));
	}

	// a · ζ mod q in (−q, q) for every 16-bit a, given ζ' = ⌊ζ · 2^15 / q⌉.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<short> MultiplyConstant(Vector128<short> a, Vector128<short> zeta, Vector128<short> zetaQuotient)
	{
		return MultiplySubtract(a * zeta, MultiplyRoundedHigh(a, zetaQuotient), Vector128.Create(Q));
	}

	// a mod q in (−0.66 q, 0.66 q) for every 16-bit a.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<short> BarrettReduce(Vector128<short> a)
	{
		return MultiplySubtract(a, MultiplyRoundedHigh(a, Vector128.Create((short)10)), Vector128.Create(Q));
	}

	// R⁻¹ · c mod q in (−q, q) for |c| < q · 2^15, with c from even[i] into lane 2i and from odd[i] into lane 2i + 1.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<short> MontgomeryReduce(Vector128<int> even, Vector128<int> odd)
	{
		Vector128<short> qInverse = Vector128.Create(MLKemConstants.QInverse);
		Vector128<short> q = Vector128.Create(Q);

		if (Sse41.IsSupported)
		{
			Vector128<short> low = Sse41.Blend(even.AsInt16(), (odd << 16).AsInt16(), 0b1010_1010);
			Vector128<short> high = Sse41.Blend((even >>> 16).AsInt16(), odd.AsInt16(), 0b1010_1010);
			return high - Sse2.MultiplyHigh(low * qInverse, q);
		}
		else
		{
			Vector128<short> low = AdvSimd.Arm64.TransposeEven(even.AsInt16(), odd.AsInt16());
			Vector128<short> high = AdvSimd.Arm64.TransposeOdd(even.AsInt16(), odd.AsInt16());

			// The doubling product is ⌊t · q / 2^15⌋, whose half rounded down is ⌊t · q / 2^16⌋.
			return high - (AdvSimd.MultiplyDoublingSaturateHigh(low * qInverse, q) >> 1);
		}
	}

	// ⌊left · right / 2^15⌉, ties rounded up.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<short> MultiplyRoundedHigh(Vector128<short> left, Vector128<short> right)
	{
		if (Ssse3.IsSupported)
		{
			return Ssse3.MultiplyHighRoundScale(left, right);
		}

		return AdvSimd.MultiplyRoundedDoublingSaturateHigh(left, right);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<short> MultiplySubtract(Vector128<short> minuend, Vector128<short> left, Vector128<short> right)
	{
		if (AdvSimd.IsSupported)
		{
			return AdvSimd.MultiplySubtract(minuend, left, right);
		}

		return minuend - left * right;
	}

	// left[2i] · right[2i] + left[2i + 1] · right[2i + 1] in 32-bit lane i.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<int> MultiplyAddAdjacent(Vector128<short> left, Vector128<short> right)
	{
		if (Sse2.IsSupported)
		{
			return Sse2.MultiplyAddAdjacent(left, right);
		}

		Vector128<int> high = AdvSimd.MultiplyWideningUpper(left, right);
		Vector128<int> low = AdvSimd.MultiplyWideningLower(left.GetLower(), right.GetLower());
		return AdvSimd.Arm64.AddPairwise(low, high);
	}

	// Bit i set for each lane i of the mask that is set, and how many are.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint ExtractMask(Vector128<short> mask, out uint count)
	{
		if (AdvSimd.Arm64.IsSupported)
		{
			count = (uint)-AdvSimd.Arm64.AddAcross(mask).ToScalar();
			return (uint)AdvSimd.Arm64.AddAcross(mask & Vector128.Create(1, 2, 4, 8, 16, 32, 64, 128)).ToScalar();
		}

		uint bits = mask.ExtractMostSignificantBits();
		count = (uint)BitOperations.PopCount(bits);
		return bits;
	}

	// Taken as four 32-bit units each: (a, b) ← ([a0, b0, a1, b1], [a2, b2, a3, b3]).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Interleave(ref Vector128<short> a, ref Vector128<short> b)
	{
		Vector128<uint> x = a.AsUInt32();
		Vector128<uint> y = b.AsUInt32();
		a = VectorTranspose.ZipLow(x, y).AsInt16();
		b = VectorTranspose.ZipHigh(x, y).AsInt16();
	}

	// The inverse of Interleave: (a, b) ← ([a0, a2, b0, b2], [a1, a3, b1, b3]).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Deinterleave(ref Vector128<short> a, ref Vector128<short> b)
	{
		if (Sse.IsSupported)
		{
			Vector128<float> x = a.AsSingle();
			Vector128<float> y = b.AsSingle();
			a = Sse.Shuffle(x, y, 0b10_00_10_00).AsInt16();
			b = Sse.Shuffle(x, y, 0b11_01_11_01).AsInt16();
		}
		else
		{
			Vector128<uint> x = a.AsUInt32();
			Vector128<uint> y = b.AsUInt32();
			a = AdvSimd.Arm64.UnzipEven(x, y).AsInt16();
			b = AdvSimd.Arm64.UnzipOdd(x, y).AsInt16();
		}
	}

	// Bytes index to index + 15 of right followed by left.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> AlignRight(Vector128<byte> left, Vector128<byte> right, [ConstantExpected(Max = 15)] byte index)
	{
		if (Ssse3.IsSupported)
		{
			return Ssse3.AlignRight(left, right, index);
		}

		return AdvSimd.ExtractVector128(right, left, index);
	}

	// The two vectors narrowed to bytes with unsigned saturation.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> PackUnsignedSaturate(Vector128<short> low, Vector128<short> high)
	{
		if (Sse2.IsSupported)
		{
			return Sse2.PackUnsignedSaturate(low, high);
		}

		return AdvSimd.ExtractNarrowingSaturateUnsignedUpper(AdvSimd.ExtractNarrowingSaturateUnsignedLower(low), high);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ushort> PackUnsignedSaturate(Vector128<int> low, Vector128<int> high)
	{
		if (Sse41.IsSupported)
		{
			return Sse41.PackUnsignedSaturate(low, high);
		}

		return AdvSimd.ExtractNarrowingSaturateUnsignedUpper(AdvSimd.ExtractNarrowingSaturateUnsignedLower(low), high);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<sbyte> ZipLow(Vector128<sbyte> left, Vector128<sbyte> right)
	{
		return Sse2.IsSupported ? Sse2.UnpackLow(left, right) : AdvSimd.Arm64.ZipLow(left, right);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<sbyte> ZipHigh(Vector128<sbyte> left, Vector128<sbyte> right)
	{
		return Sse2.IsSupported ? Sse2.UnpackHigh(left, right) : AdvSimd.Arm64.ZipHigh(left, right);
	}

	// The coefficients mod q in [0, q), combined in pairs into the 24 low bits of each 32-bit lane.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> Pack12(Vector128<short> f)
	{
		Vector128<short> canonical = f + (f >> 15 & Vector128.Create(Q));
		return MultiplyAddAdjacent(canonical, Vector128.Create(1, 4096, 1, 4096, 1, 4096, 1, 4096)).AsByte();
	}

	// The eight 12-bit values of bytes offset to offset + 11.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<short> Unpack12(Vector128<byte> source, [ConstantExpected(Max = 4)] byte offset)
	{
		Vector128<byte> indices = Vector128.Create((byte)0, 1, 1, 2, 3, 4, 4, 5, 6, 7, 7, 8, 9, 10, 10, 11) + Vector128.Create(offset);
		Vector128<ushort> windows = Vector128.Shuffle(source, indices).AsUInt16();
		return (windows * Vector128.Create((ushort)16, 1, 16, 1, 16, 1, 16, 1) >>> 4).AsInt16();
	}

	// ⌊2^d · x / q⌉ mod 2^d, which is Compress_d of x mod q for x in (−q, q).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<short> CompressValues(Vector128<short> x, [ConstantExpected(Min = 1, Max = 11)] int bits)
	{
		Vector128<short> y = MultiplyRoundedHigh(x, Vector128.Create((short)(((1 << 15 + bits) + Q / 2) / Q)));
		Vector128<short> remainder = MultiplySubtract(x << bits, y, Vector128.Create(Q));
		Vector128<short> half = Vector128.Create((short)(Q / 2));
		y = y - Vector128.GreaterThan(remainder, half) + Vector128.LessThan(remainder, -half);
		return y & Vector128.Create((short)((1 << bits) - 1));
	}

	// Each four vectors make one 32-bit word, a bit per byte gathered from the signs of saturated bytes.
	private static void Compress1(ref short f, ref byte destination)
	{
		for (nuint i = 0; i < N; i += 32)
		{
			Vector128<short> y0 = CompressValues(Vector128.LoadUnsafe(ref f, i), 1) << 15;
			Vector128<short> y1 = CompressValues(Vector128.LoadUnsafe(ref f, i + 8), 1) << 15;
			Vector128<short> y2 = CompressValues(Vector128.LoadUnsafe(ref f, i + 16), 1) << 15;
			Vector128<short> y3 = CompressValues(Vector128.LoadUnsafe(ref f, i + 24), 1) << 15;
			uint low = Vector128.ExtractMostSignificantBits(Vector128.NarrowWithSaturation(y0, y1));
			uint high = Vector128.ExtractMostSignificantBits(Vector128.NarrowWithSaturation(y2, y3));
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, i / 8), low | high << 16);
		}
	}

	// Each pair of values becomes a byte in a 32-bit lane, and four vectors narrow to one.
	private static void Compress4(ref short f, ref byte destination)
	{
		Vector128<short> weights = Vector128.Create(1, 16, 1, 16, 1, 16, 1, 16);

		for (nuint i = 0; i < N; i += 32)
		{
			Vector128<int> p0 = MultiplyAddAdjacent(CompressValues(Vector128.LoadUnsafe(ref f, i), 4), weights);
			Vector128<int> p1 = MultiplyAddAdjacent(CompressValues(Vector128.LoadUnsafe(ref f, i + 8), 4), weights);
			Vector128<int> p2 = MultiplyAddAdjacent(CompressValues(Vector128.LoadUnsafe(ref f, i + 16), 4), weights);
			Vector128<int> p3 = MultiplyAddAdjacent(CompressValues(Vector128.LoadUnsafe(ref f, i + 24), 4), weights);
			PackUnsignedSaturate(Vector128.NarrowWithSaturation(p0, p1), Vector128.NarrowWithSaturation(p2, p3)).StoreUnsafe(ref destination, i / 2);
		}
	}

	// Each two vectors make ten bytes. Writing 16 bytes at a time overruns into the next unit, which overwrites it, except at the end.
	private static void Compress5(ref short f, ref byte destination)
	{
		nuint offset = 0;

		for (nuint i = 0; i < N - 16; i += 16, offset += 10)
		{
			Pack5(ref f, i).StoreUnsafe(ref destination, offset);
		}

		StorePartial(Pack5(ref f, N - 16), ref Unsafe.Add(ref destination, offset), 10);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> Pack5(ref short f, nuint index)
	{
		Vector128<short> weights = Vector128.Create(1, 32, 4, 128, 16, 512, 64, 2048);
		Vector128<int> p0 = MultiplyAddAdjacent(CompressValues(Vector128.LoadUnsafe(ref f, index), 5), weights);
		Vector128<int> p1 = MultiplyAddAdjacent(CompressValues(Vector128.LoadUnsafe(ref f, index + 8), 5), weights);
		Vector128<byte> lanes = PackUnsignedSaturate(p0, p1).AsByte();
		return Vector128.Shuffle(lanes, Vector128.Create(0, 1, 4, 5, Zero, 8, 9, 12, 13, Zero, Zero, Zero, Zero, Zero, Zero, Zero))
			| Vector128.Shuffle(lanes, Vector128.Create(Zero, 2, 3, 6, 7, Zero, 10, 11, 14, 15, Zero, Zero, Zero, Zero, Zero, Zero));
	}

	// Each vector makes ten bytes.
	private static void Compress10(ref short f, ref byte destination)
	{
		nuint offset = 0;

		for (nuint i = 0; i < N - 8; i += 8, offset += 10)
		{
			Pack10(Vector128.LoadUnsafe(ref f, i)).StoreUnsafe(ref destination, offset);
		}

		StorePartial(Pack10(Vector128.LoadUnsafe(ref f, N - 8)), ref Unsafe.Add(ref destination, offset), 10);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> Pack10(Vector128<short> f)
	{
		Vector128<short> weights = Vector128.Create(1, 1024, 16, 16384, 1, 1024, 16, 16384);
		Vector128<byte> lanes = MultiplyAddAdjacent(CompressValues(f, 10), weights).AsByte();
		return Vector128.Shuffle(lanes, Vector128.Create(0, 1, 2, Zero, Zero, 8, 9, 10, Zero, Zero, Zero, Zero, Zero, Zero, Zero, Zero))
			| Vector128.Shuffle(lanes, Vector128.Create(Zero, Zero, 4, 5, 6, Zero, Zero, 12, 13, 14, Zero, Zero, Zero, Zero, Zero, Zero));
	}

	// Each vector makes eleven bytes.
	private static void Compress11(ref short f, ref byte destination)
	{
		nuint offset = 0;

		for (nuint i = 0; i < N - 8; i += 8, offset += 11)
		{
			Pack11(Vector128.LoadUnsafe(ref f, i)).StoreUnsafe(ref destination, offset);
		}

		StorePartial(Pack11(Vector128.LoadUnsafe(ref f, N - 8)), ref Unsafe.Add(ref destination, offset), 11);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> Pack11(Vector128<short> f)
	{
		Vector128<short> y = CompressValues(f, 11) * Vector128.Create(1, 1, 1, 16, 1, 2, 1, 1);
		Vector128<short> weights = Vector128.Create(1, 2048, 64, 8192, 16, 16384, 4, 8192);
		Vector128<byte> lanes = MultiplyAddAdjacent(y, weights).AsByte();
		return Vector128.Shuffle(lanes, Vector128.Create(0, 1, 2, Zero, Zero, 8, 9, 10, 11, Zero, Zero, Zero, Zero, Zero, Zero, Zero))
			| Vector128.Shuffle(lanes, Vector128.Create(Zero, Zero, 4, 5, 6, 7, Zero, Zero, 12, 13, 14, Zero, Zero, Zero, Zero, Zero));
	}

	// The first length bytes of value.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StorePartial(Vector128<byte> value, ref byte destination, [ConstantExpected(Min = 10, Max = 11)] int length)
	{
		Unsafe.WriteUnaligned(ref destination, value.AsUInt64().ToScalar());
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 8), value.AsUInt16().GetElement(4));

		if (length is 11)
		{
			Unsafe.Add(ref destination, 10) = value.GetElement(10);
		}
	}

	// Each vector comes from d bytes; near the end the load moves back rather than read past it.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Decompress(ref byte source, ref short f, [ConstantExpected(Min = 1, Max = 11)] int bits)
	{
		nuint last = 32 * (nuint)bits - 16;
		nuint i = 0;
		nuint offset = 0;

		for (; offset <= last; i += 8, offset += (nuint)bits)
		{
			DecompressValues(Vector128.LoadUnsafe(ref source, offset), DecompressIndices(bits), bits).StoreUnsafe(ref f, i);
		}

		for (; i < N; i += 8, offset += (nuint)bits)
		{
			Vector128<byte> indices = DecompressIndices(bits) + Vector128.Create((byte)(offset - last));
			DecompressValues(Vector128.LoadUnsafe(ref source, last), indices, bits).StoreUnsafe(ref f, i);
		}
	}

	// For d ≤ 10, lane i takes the one or two bytes holding bits d · i to d · i + d − 1. For d = 11, 32-bit lane i takes the up to four bytes holding values 2i and 2i + 1.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> DecompressIndices([ConstantExpected(Min = 1, Max = 11)] int bits)
	{
		return bits switch
		{
			1 => Vector128<byte>.Zero,
			4 => Vector128.Create((byte)0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3),
			5 => Vector128.Create((byte)0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4),
			10 => Vector128.Create((byte)0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 6, 7, 7, 8, 8, 9),
			_ => Vector128.Create((byte)0, 1, 2, 2, 2, 3, 4, 5, 5, 6, 7, 8, 8, 9, 10, 10)
		};
	}

	// Decompress_d(y) = ⌊q · y / 2^d⌉ = ⌊(y · 2^(15 − d)) · q / 2^15⌉.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<short> DecompressValues(Vector128<byte> source, Vector128<byte> indices, [ConstantExpected(Min = 1, Max = 11)] int bits)
	{
		Vector128<byte> windows = Vector128.Shuffle(source, indices);
		Vector128<short> scaled;

		if (bits is 11)
		{
			Vector128<uint> pairs = windows.AsUInt32();
			Vector128<uint> even = pairs * Vector128.Create(1u << 21, 1u << 15, 1u << 17, 1u << 19) >>> 17 & Vector128.Create(0x7FF0u);
			Vector128<uint> odd = pairs * Vector128.Create(1u << 10, 1u << 4, 1u << 6, 1u << 8) >>> 1 & Vector128.Create(0x7FF0_0000u);
			scaled = (even | odd).AsInt16();
		}
		else
		{
			Vector128<ushort> multipliers = bits switch
			{
				1 => Vector128.Create(1 << 15, 1 << 14, 1 << 13, 1 << 12, 1 << 11, 1 << 10, 1 << 9, 1 << 8),
				4 => Vector128.Create((ushort)(1 << 12), 1 << 8, 1 << 12, 1 << 8, 1 << 12, 1 << 8, 1 << 12, 1 << 8),
				5 => Vector128.Create((ushort)(1 << 11), 1 << 6, 1 << 9, 1 << 4, 1 << 7, 1 << 10, 1 << 5, 1 << 8),
				_ => Vector128.Create((ushort)(1 << 6), 1 << 4, 1 << 2, 1, 1 << 6, 1 << 4, 1 << 2, 1)
			};
			Vector128<ushort> mask = Vector128.Create((ushort)((1 << bits) - 1 << 15 - bits));
			scaled = (windows.AsUInt16() * multipliers >>> 1 & mask).AsInt16();
		}

		return MultiplyRoundedHigh(scaled, Vector128.Create(Q));
	}

	// A table of 16 entries gives b0 + b1 − b2 − b3 of each four bits.
	private static void SampleCbd2(ref byte source, ref short f)
	{
		Vector128<sbyte> values = Vector128.Create(0, 1, 1, 2, -1, 0, 0, 1, -1, 0, 0, 1, -2, -1, -1, 0);

		for (nuint i = 0; i < N / 2; i += 16)
		{
			Vector128<byte> bytes = Vector128.LoadUnsafe(ref source, i);
			Vector128<sbyte> low = Vector128.ShuffleNative(values, (bytes & Vector128.Create((byte)0x0F)).AsSByte());
			Vector128<sbyte> high = Vector128.ShuffleNative(values, (bytes >>> 4).AsSByte());
			Vector128<sbyte> first = ZipLow(low, high);
			Vector128<sbyte> second = ZipHigh(low, high);
			Vector128.WidenLower(first).StoreUnsafe(ref f, 2 * i);
			Vector128.WidenUpper(first).StoreUnsafe(ref f, 2 * i + 8);
			Vector128.WidenLower(second).StoreUnsafe(ref f, 2 * i + 16);
			Vector128.WidenUpper(second).StoreUnsafe(ref f, 2 * i + 24);
		}
	}

	// Three loads of 16 bytes make four groups of 12 bytes, each 16 coefficients.
	private static void SampleCbd3(ref byte source, ref short f)
	{
		for (nuint i = 0, offset = 0; i < N; i += 64, offset += 48)
		{
			Vector128<byte> b0 = Vector128.LoadUnsafe(ref source, offset);
			Vector128<byte> b1 = Vector128.LoadUnsafe(ref source, offset + 16);
			Vector128<byte> b2 = Vector128.LoadUnsafe(ref source, offset + 32);
			SampleCbd3Group(b0, 0, ref f, i);
			SampleCbd3Group(AlignRight(b1, b0, 12), 0, ref f, i + 16);
			SampleCbd3Group(AlignRight(b2, b1, 8), 0, ref f, i + 32);
			SampleCbd3Group(b2, 4, ref f, i + 48);
		}
	}

	// Coefficient i is the sum of bits 6i to 6i + 2 minus that of bits 6i + 3 to 6i + 5.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void SampleCbd3Group(Vector128<byte> source, [ConstantExpected(Max = 4)] byte offset, ref short f, nuint index)
	{
		Vector128<byte> groups = Vector128.Shuffle(source, Vector128.Create
		(
			offset, (byte)(offset + 1), (byte)(offset + 2), Zero, (byte)(offset + 3), (byte)(offset + 4), (byte)(offset + 5), Zero,
			(byte)(offset + 6), (byte)(offset + 7), (byte)(offset + 8), Zero, (byte)(offset + 9), (byte)(offset + 10), (byte)(offset + 11), Zero
		));
		Vector128<uint> bits = groups.AsUInt32();
		Vector128<uint> mask = Vector128.Create(0x249249u);
		Vector128<byte> sums = ((bits & mask) + (bits >>> 1 & mask) + (bits >>> 2 & mask)).AsByte();
		Vector128<ushort> multipliers = Vector128.Create((ushort)(1 << 10), 1 << 4, 1 << 6, 1 << 8, 1 << 10, 1 << 4, 1 << 6, 1 << 8);
		Vector128<ushort> low = Vector128.Shuffle(sums, Vector128.Create((byte)0, 1, 0, 1, 1, 2, 2, 3, 4, 5, 4, 5, 5, 6, 6, 7)).AsUInt16() * multipliers;
		Vector128<ushort> high = Vector128.Shuffle(sums, Vector128.Create((byte)8, 9, 8, 9, 9, 10, 10, 11, 12, 13, 12, 13, 13, 14, 14, 15)).AsUInt16() * multipliers;
		((low >>> 10 & Vector128.Create((ushort)7)) - (low >>> 13)).AsInt16().StoreUnsafe(ref f, index);
		((high >>> 10 & Vector128.Create((ushort)7)) - (high >>> 13)).AsInt16().StoreUnsafe(ref f, index + 8);
	}
}
