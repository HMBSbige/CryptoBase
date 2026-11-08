namespace CryptoBase.EllipticCurves.SM9;

internal readonly struct SM9VectorAvx512 : ISM9Vector<SM9VectorAvx512>
{
	private readonly Vector512<ulong> _value;

	private SM9VectorAvx512(Vector512<ulong> value)
	{
		_value = value;
	}

	public static bool IsSupported => Avx512F.IsSupported && Vector512.IsHardwareAccelerated;

	public static int Count => Vector512<ulong>.Count;

	public static int RegisterCount => 32;

	public static SM9VectorAvx512 Zero => default;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx512 Create(ulong value)
	{
		return new SM9VectorAvx512(Vector512.Create(value));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx512 Load(ref readonly ulong source)
	{
		return new SM9VectorAvx512(Vector512.LoadUnsafe(in source));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx512 LoadBroadcast(ref readonly ulong source)
	{
		return new SM9VectorAvx512(Vector512.Create(source));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe SM9VectorAvx512 LoadPairBroadcast(ref readonly ulong source)
	{
		return new SM9VectorAvx512(Avx512F.BroadcastVector128ToVector512((uint*)Unsafe.AsPointer(ref Unsafe.AsRef(in source))).AsUInt64());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Store(ref ulong destination)
	{
		_value.StoreUnsafe(ref destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx512 operator +(SM9VectorAvx512 left, SM9VectorAvx512 right)
	{
		return new SM9VectorAvx512(left._value + right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx512 operator -(SM9VectorAvx512 left, SM9VectorAvx512 right)
	{
		return new SM9VectorAvx512(left._value - right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx512 operator &(SM9VectorAvx512 left, SM9VectorAvx512 right)
	{
		return new SM9VectorAvx512(left._value & right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx512 operator |(SM9VectorAvx512 left, SM9VectorAvx512 right)
	{
		return new SM9VectorAvx512(left._value | right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx512 operator <<(SM9VectorAvx512 value, int shift)
	{
		return new SM9VectorAvx512(value._value << shift);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx512 operator >>>(SM9VectorAvx512 value, int shift)
	{
		return new SM9VectorAvx512(value._value >>> shift);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx512 Multiply(SM9VectorAvx512 left, SM9VectorAvx512 right)
	{
		return new SM9VectorAvx512(Avx512F.Multiply(left._value.AsUInt32(), right._value.AsUInt32()));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx512 MultiplyAdd(SM9VectorAvx512 addend, SM9VectorAvx512 left, SM9VectorAvx512 right)
	{
		return addend + Multiply(left, right);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx512 MultiplyByFactor(SM9VectorAvx512 left, uint factor)
	{
		return Multiply(left, Create(factor));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx512 MultiplyAddByFactor(SM9VectorAvx512 addend, SM9VectorAvx512 left, uint factor)
	{
		return addend + Multiply(left, Create(factor));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx512 ShiftRightArithmetic26(SM9VectorAvx512 value)
	{
		return new SM9VectorAvx512((value._value.AsInt64() >> 26).AsUInt64());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx512 ConditionalSelect(SM9VectorAvx512 mask, SM9VectorAvx512 whenSet, SM9VectorAvx512 whenClear)
	{
		return new SM9VectorAvx512(Vector512.ConditionalSelect(mask._value, whenSet._value, whenClear._value));
	}

	// One vpermt2q of the two rows.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Permute(ref readonly ulong first, ref readonly ulong second, ref ulong destination, ulong pattern)
	{
		Vector512<ulong> indices = Vector512.Create(pattern & 15, pattern >> 4 & 15, pattern >> 8 & 15, pattern >> 12 & 15, pattern >> 16 & 15, pattern >> 20 & 15, pattern >> 24 & 15, pattern >> 28 & 15);
		Avx512F.PermuteVar8x64x2(Vector512.LoadUnsafe(in first), indices, Vector512.LoadUnsafe(in second)).StoreUnsafe(ref destination);
	}

	// Permute writes every lane already.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void PermuteFull(ref readonly ulong first, ref readonly ulong second, ref ulong destination, ulong pattern)
	{
		Permute(in first, in second, ref destination, pattern);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx512 Permute(SM9VectorAvx512 first, SM9VectorAvx512 second, ulong pattern)
	{
		Vector512<ulong> indices = Vector512.Create(pattern & 15, pattern >> 4 & 15, pattern >> 8 & 15, pattern >> 12 & 15, pattern >> 16 & 15, pattern >> 20 & 15, pattern >> 24 & 15, pattern >> 28 & 15);
		return new SM9VectorAvx512(Avx512F.PermuteVar8x64x2(first._value, indices, second._value));
	}
}
