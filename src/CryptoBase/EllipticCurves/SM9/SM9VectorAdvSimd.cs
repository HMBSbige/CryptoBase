namespace CryptoBase.EllipticCurves.SM9;

// The lanes of ISM9Vector in one vector of AdvSimd, whose products take umull and umlal on the low halves of the lanes, narrowed by xtn.
internal readonly struct SM9VectorAdvSimd : ISM9Vector<SM9VectorAdvSimd>
{
	private readonly Vector128<ulong> _value;

	private SM9VectorAdvSimd(Vector128<ulong> value)
	{
		_value = value;
	}

	public static bool IsSupported => AdvSimd.Arm64.IsSupported && Vector128.IsHardwareAccelerated;

	public static int Count => Vector128<ulong>.Count;

	public static int RegisterCount => 32;

	public static SM9VectorAdvSimd Zero => default;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAdvSimd Create(ulong value)
	{
		return new SM9VectorAdvSimd(Vector128.Create(value));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAdvSimd Load(ref readonly ulong source)
	{
		return new SM9VectorAdvSimd(Vector128.LoadUnsafe(in source));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAdvSimd LoadBroadcast(ref readonly ulong source)
	{
		return new SM9VectorAdvSimd(Vector128.Create(source));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAdvSimd LoadPairBroadcast(ref readonly ulong source)
	{
		return new SM9VectorAdvSimd(Vector128.LoadUnsafe(in source));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Store(ref ulong destination)
	{
		_value.StoreUnsafe(ref destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAdvSimd operator +(SM9VectorAdvSimd left, SM9VectorAdvSimd right)
	{
		return new SM9VectorAdvSimd(left._value + right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAdvSimd operator -(SM9VectorAdvSimd left, SM9VectorAdvSimd right)
	{
		return new SM9VectorAdvSimd(left._value - right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAdvSimd operator &(SM9VectorAdvSimd left, SM9VectorAdvSimd right)
	{
		return new SM9VectorAdvSimd(left._value & right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAdvSimd operator |(SM9VectorAdvSimd left, SM9VectorAdvSimd right)
	{
		return new SM9VectorAdvSimd(left._value | right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAdvSimd operator <<(SM9VectorAdvSimd value, int shift)
	{
		return new SM9VectorAdvSimd(value._value << shift);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAdvSimd operator >>>(SM9VectorAdvSimd value, int shift)
	{
		return new SM9VectorAdvSimd(value._value >>> shift);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAdvSimd Multiply(SM9VectorAdvSimd left, SM9VectorAdvSimd right)
	{
		return new SM9VectorAdvSimd(AdvSimd.MultiplyWideningLower(AdvSimd.ExtractNarrowingLower(left._value), AdvSimd.ExtractNarrowingLower(right._value)));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAdvSimd MultiplyAdd(SM9VectorAdvSimd addend, SM9VectorAdvSimd left, SM9VectorAdvSimd right)
	{
		return new SM9VectorAdvSimd(AdvSimd.MultiplyWideningLowerAndAdd(addend._value, AdvSimd.ExtractNarrowingLower(left._value), AdvSimd.ExtractNarrowingLower(right._value)));
	}

	// The factor goes in as a constant of two lanes of 32 bits, with no narrowing of its own.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAdvSimd MultiplyByFactor(SM9VectorAdvSimd left, uint factor)
	{
		return new SM9VectorAdvSimd(AdvSimd.MultiplyWideningLower(AdvSimd.ExtractNarrowingLower(left._value), Vector64.Create(factor)));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAdvSimd MultiplyAddByFactor(SM9VectorAdvSimd addend, SM9VectorAdvSimd left, uint factor)
	{
		return new SM9VectorAdvSimd(AdvSimd.MultiplyWideningLowerAndAdd(addend._value, AdvSimd.ExtractNarrowingLower(left._value), Vector64.Create(factor)));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAdvSimd ShiftRightArithmetic26(SM9VectorAdvSimd value)
	{
		return new SM9VectorAdvSimd(AdvSimd.ShiftRightArithmetic(value._value.AsInt64(), 26).AsUInt64());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAdvSimd ConditionalSelect(SM9VectorAdvSimd mask, SM9VectorAdvSimd whenSet, SM9VectorAdvSimd whenClear)
	{
		return new SM9VectorAdvSimd(AdvSimd.BitwiseSelect(mask._value, whenSet._value, whenClear._value));
	}

	// Each pair of lanes of the destination row from the two pairs that hold its sources, by one zip1, zip2, ext or ins; the pattern is a constant, so the addresses and the choice fold. Every source is read before the destination is written. Lanes 6 and 7, padding, are left as they were.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Permute(ref readonly ulong first, ref readonly ulong second, ref ulong destination, ulong pattern)
	{
		Vector128<ulong> p0 = Pair(in first, in second, pattern & 15, pattern >> 4 & 15);
		Vector128<ulong> p1 = Pair(in first, in second, pattern >> 8 & 15, pattern >> 12 & 15);
		Vector128<ulong> p2 = Pair(in first, in second, pattern >> 16 & 15, pattern >> 20 & 15);
		p0.StoreUnsafe(ref destination);
		p1.StoreUnsafe(ref Unsafe.Add(ref destination, 2));
		p2.StoreUnsafe(ref Unsafe.Add(ref destination, 4));
	}

	// As Permute with the fourth pair, lanes 6 and 7, as well.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void PermuteFull(ref readonly ulong first, ref readonly ulong second, ref ulong destination, ulong pattern)
	{
		Vector128<ulong> p0 = Pair(in first, in second, pattern & 15, pattern >> 4 & 15);
		Vector128<ulong> p1 = Pair(in first, in second, pattern >> 8 & 15, pattern >> 12 & 15);
		Vector128<ulong> p2 = Pair(in first, in second, pattern >> 16 & 15, pattern >> 20 & 15);
		Vector128<ulong> p3 = Pair(in first, in second, pattern >> 24 & 15, pattern >> 28 & 15);
		p0.StoreUnsafe(ref destination);
		p1.StoreUnsafe(ref Unsafe.Add(ref destination, 2));
		p2.StoreUnsafe(ref Unsafe.Add(ref destination, 4));
		p3.StoreUnsafe(ref Unsafe.Add(ref destination, 6));
	}

	// (lane x, lane y) of the sixteen lanes of the two rows.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> Pair(ref readonly ulong first, ref readonly ulong second, ulong x, ulong y)
	{
		Vector128<ulong> left = Vector128.LoadUnsafe(in Source(in first, in second, x & 14));
		Vector128<ulong> right = Vector128.LoadUnsafe(in Source(in first, in second, y & 14));

		return ((x & 1) << 1 | y & 1) switch
		{
			0 => AdvSimd.Arm64.ZipLow(left, right),
			1 => AdvSimd.Arm64.InsertSelectedScalar(left, 1, right, 1),
			2 => AdvSimd.ExtractVector128(left, right, 1),
			_ => AdvSimd.Arm64.ZipHigh(left, right),
		};
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ref readonly ulong Source(ref readonly ulong first, ref readonly ulong second, ulong n)
	{
		return ref n < 8 ? ref Unsafe.Add(ref Unsafe.AsRef(in first), (nint)n) : ref Unsafe.Add(ref Unsafe.AsRef(in second), (nint)n - 8);
	}

	// A row of eight lanes spans several vectors of this type, so the kernels never take this.
	public static SM9VectorAdvSimd Permute(SM9VectorAdvSimd first, SM9VectorAdvSimd second, ulong pattern)
	{
		throw new UnreachableException();
	}

}
