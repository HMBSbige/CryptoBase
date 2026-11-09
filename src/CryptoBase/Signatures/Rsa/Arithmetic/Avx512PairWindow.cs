namespace CryptoBase.Signatures.Rsa.Arithmetic;

// The vectors of MontgomeryPairKernelAvx512, as IAvx512Window describes them for MontgomeryKernelAvx512, with the digits of two moduli in alternate lanes: a digit is two lanes wide, so that the shift and the carries move by two lanes. Load and Store take pointers as there, to words and result that the kernel pins.
internal struct Avx512PairWindow : IAvx512Window<Avx512PairWindow>
{
	private const ulong Mask = (1UL << 52) - 1;

	private Vector512<double> _digits;
	private Vector512<ulong> _lanes;
	private Vector512<ulong> _high;

	public static int Count
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => 1;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe void Load(ref Avx512PairWindow window, ref ulong words, int length, int index)
	{
		int remaining = length - 8 * index;
		Vector512<ulong> value = remaining >= 8 ? Vector512.LoadUnsafe(ref words, (nuint)(8 * index)) : Avx512F.MaskLoad((ulong*)Unsafe.AsPointer(ref Unsafe.Add(ref words, 8 * index)), LaneMask(remaining), Vector512<ulong>.Zero);
		window._digits = Avx512DQ.ConvertToVector512Double(value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Accumulate(ref Avx512PairWindow acc, ref readonly Avx512PairWindow a, ref readonly Avx512PairWindow n, Vector512<double> b, Vector512<double> m, Vector512<double> high, Vector512<double> low)
	{
		Vector512<double> t1 = Avx512F.FusedMultiplyAdd(a._digits, b, high, FloatRoundingMode.ToNegativeInfinity);
		Vector512<double> t2 = Avx512F.FusedMultiplyAdd(n._digits, m, high, FloatRoundingMode.ToNegativeInfinity);
		Vector512<double> l1 = Avx512F.FusedMultiplyAdd(a._digits, b, low - t1);
		Vector512<double> l2 = Avx512F.FusedMultiplyAdd(n._digits, m, low - t2);
		acc._lanes += l1.AsUInt64() + l2.AsUInt64();
		acc._high = t1.AsUInt64() + t2.AsUInt64();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Shift(ref Avx512PairWindow acc, Vector512<ulong> next)
	{
		acc._lanes = Avx512F.AlignRight64(next, acc._lanes, 2) + acc._high;
	}

	public static Vector512<ulong> First(ref readonly Avx512PairWindow acc)
	{
		return acc._lanes;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ReplaceLow(ref Avx512PairWindow acc, Vector512<ulong> low, Vector512<ulong> mask)
	{
		acc._lanes = Vector512.ConditionalSelect(mask, low, acc._lanes);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<ulong> Pass(ref Avx512PairWindow acc, Vector512<ulong> offset, Vector512<ulong> previous)
	{
		Vector512<ulong> value = acc._lanes - offset;
		Vector512<ulong> carry = value >> 52;
		acc._lanes = (value & Vector512.Create(Mask)) + Avx512F.AlignRight64(carry, previous, 6);
		return carry;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Masks(ref readonly Avx512PairWindow acc, int index, Span<ulong> generate, Span<ulong> propagate)
	{
		generate[index >> 3] |= Vector512.GreaterThan(acc._lanes, Vector512.Create(Mask)).ExtractMostSignificantBits() << 8 * (index & 7);
		propagate[index >> 3] |= Vector512.Equals(acc._lanes, Vector512.Create(Mask)).ExtractMostSignificantBits() << 8 * (index & 7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe void Store(ref readonly Avx512PairWindow acc, int index, ReadOnlySpan<ulong> carries, ref ulong result, int length)
	{
		ulong bits = carries[index >> 3] >> 8 * (index & 7);
		Vector512<ulong> value = acc._lanes + (Avx512F.ShiftRightLogicalVariable(Vector512.Create(bits), Vector512<ulong>.Indices) & Vector512<ulong>.One) & Vector512.Create(Mask);
		int remaining = length - 8 * index;

		if (remaining >= 8)
		{
			value.StoreUnsafe(ref result, (nuint)(8 * index));
		}
		else if (remaining > 0)
		{
			Avx512F.MaskStore((ulong*)Unsafe.AsPointer(ref Unsafe.Add(ref result, 8 * index)), LaneMask(remaining), value);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> LaneMask(int count)
	{
		return Vector512.LessThan(Vector512<ulong>.Indices, Vector512.Create((ulong)Math.Max(count, 0)));
	}
}
