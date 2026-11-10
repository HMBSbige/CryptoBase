namespace CryptoBase.EllipticCurves.SM9;

internal readonly struct SM9VectorSse41 : ISM9Vector<SM9VectorSse41>
{
	private readonly Vector128<ulong> _value;

	private SM9VectorSse41(Vector128<ulong> value)
	{
		_value = value;
	}

	public static bool IsSupported => Sse41.IsSupported && Vector128.IsHardwareAccelerated;

	public static int Count => Vector128<ulong>.Count;

	public static int RegisterCount => 16;

	public static SM9VectorSse41 Zero => default;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorSse41 Create(ulong value)
	{
		return new SM9VectorSse41(Vector128.Create(value));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorSse41 Load(ref readonly ulong source)
	{
		return new SM9VectorSse41(Vector128.LoadUnsafe(in source));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorSse41 LoadBroadcast(ref readonly ulong source)
	{
		return new SM9VectorSse41(Vector128.Create(source));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorSse41 LoadPairBroadcast(ref readonly ulong source)
	{
		return new SM9VectorSse41(Vector128.LoadUnsafe(in source));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Store(ref ulong destination)
	{
		_value.StoreUnsafe(ref destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorSse41 operator +(SM9VectorSse41 left, SM9VectorSse41 right)
	{
		return new SM9VectorSse41(left._value + right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorSse41 operator -(SM9VectorSse41 left, SM9VectorSse41 right)
	{
		return new SM9VectorSse41(left._value - right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorSse41 operator &(SM9VectorSse41 left, SM9VectorSse41 right)
	{
		return new SM9VectorSse41(left._value & right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorSse41 operator |(SM9VectorSse41 left, SM9VectorSse41 right)
	{
		return new SM9VectorSse41(left._value | right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorSse41 operator <<(SM9VectorSse41 value, int shift)
	{
		return new SM9VectorSse41(value._value << shift);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorSse41 operator >>>(SM9VectorSse41 value, int shift)
	{
		return new SM9VectorSse41(value._value >>> shift);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorSse41 Multiply(SM9VectorSse41 left, SM9VectorSse41 right)
	{
		return new SM9VectorSse41(Sse2.Multiply(left._value.AsUInt32(), right._value.AsUInt32()));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorSse41 MultiplyAdd(SM9VectorSse41 addend, SM9VectorSse41 left, SM9VectorSse41 right)
	{
		return addend + Multiply(left, right);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorSse41 MultiplyByFactor(SM9VectorSse41 left, uint factor)
	{
		return Multiply(left, Create(factor));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorSse41 MultiplyAddByFactor(SM9VectorSse41 addend, SM9VectorSse41 left, uint factor)
	{
		return addend + Multiply(left, Create(factor));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorSse41 ShiftRightArithmetic26(SM9VectorSse41 value)
	{
		if (Avx512F.VL.IsSupported)
		{
			return new SM9VectorSse41(Avx512F.VL.ShiftRightArithmetic(value._value.AsInt64(), 26).AsUInt64());
		}

		// SSE has no arithmetic shift of 64-bit lanes: with the sign bit flipped the value is offset by 2^63, which the logical shift takes to 2^37.
		return new SM9VectorSse41(((value._value ^ Vector128.Create(1UL << 63)) >>> 26) - Vector128.Create(1UL << 37));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorSse41 ConditionalSelect(SM9VectorSse41 mask, SM9VectorSse41 whenSet, SM9VectorSse41 whenClear)
	{
		return new SM9VectorSse41(Vector128.ConditionalSelect(mask._value, whenSet._value, whenClear._value));
	}

	// Each pair of lanes of the destination row from the two pairs that hold its sources, by one shufpd; the pattern is a constant, so the addresses and the controls fold. Every source is read before the destination is written. Lanes 6 and 7, padding, are left as they were.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Permute(ref readonly ulong first, ref readonly ulong second, ref ulong destination, ulong pattern)
	{
		Vector128<double> p0 = Pair(in first, in second, pattern & 15, pattern >> 4 & 15);
		Vector128<double> p1 = Pair(in first, in second, pattern >> 8 & 15, pattern >> 12 & 15);
		Vector128<double> p2 = Pair(in first, in second, pattern >> 16 & 15, pattern >> 20 & 15);
		p0.AsUInt64().StoreUnsafe(ref destination);
		p1.AsUInt64().StoreUnsafe(ref Unsafe.Add(ref destination, 2));
		p2.AsUInt64().StoreUnsafe(ref Unsafe.Add(ref destination, 4));
	}

	// As Permute with the fourth pair, lanes 6 and 7, as well, read before Permute writes, as the destination may be a source.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void PermuteFull(ref readonly ulong first, ref readonly ulong second, ref ulong destination, ulong pattern)
	{
		Vector128<double> p3 = Pair(in first, in second, pattern >> 24 & 15, pattern >> 28 & 15);
		Permute(in first, in second, ref destination, pattern);
		p3.AsUInt64().StoreUnsafe(ref Unsafe.Add(ref destination, 6));
	}

	// (lane x, lane y) of the sixteen lanes of the two rows; the control folds to a constant once Permute is inlined with a constant pattern.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<double> Pair(ref readonly ulong first, ref readonly ulong second, ulong x, ulong y)
	{
		Vector128<double> left = Vector128.LoadUnsafe(in Source(in first, in second, x & 14)).AsDouble();
		Vector128<double> right = Vector128.LoadUnsafe(in Source(in first, in second, y & 14)).AsDouble();
#pragma warning disable CA1857
		// ReSharper disable once ConstantExpected
		return Sse2.Shuffle(left, right, (byte)(x & 1 | (y & 1) << 1));
#pragma warning restore CA1857
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ref readonly ulong Source(ref readonly ulong first, ref readonly ulong second, ulong n)
	{
		return ref n < 8 ? ref Unsafe.Add(ref Unsafe.AsRef(in first), (nint)n) : ref Unsafe.Add(ref Unsafe.AsRef(in second), (nint)n - 8);
	}

	// A row of eight lanes spans several vectors of this type, so the kernels never take this.
	public static SM9VectorSse41 Permute(SM9VectorSse41 first, SM9VectorSse41 second, ulong pattern)
	{
		throw new UnreachableException();
	}

}
