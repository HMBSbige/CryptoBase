namespace CryptoBase.EllipticCurves.Curve448;

internal readonly struct Field448Vector256 : IField448Vector<Vector256<ulong>>
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<ulong> Create(ulong value)
	{
		return Vector256.Create(value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<ulong> Add(Vector256<ulong> left, Vector256<ulong> right)
	{
		return left + right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<ulong> Subtract(Vector256<ulong> left, Vector256<ulong> right)
	{
		return left - right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<ulong> And(Vector256<ulong> left, Vector256<ulong> right)
	{
		return left & right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<ulong> Xor(Vector256<ulong> left, Vector256<ulong> right)
	{
		return left ^ right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<ulong> ShiftRight(Vector256<ulong> value, int shift)
	{
		return value >> shift;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<ulong> MultiplyAdd(Vector256<ulong> addend, Vector256<ulong> left, Vector256<ulong> right)
	{
		return addend + Avx2.Multiply(left.AsUInt32(), right.AsUInt32());
	}
}
