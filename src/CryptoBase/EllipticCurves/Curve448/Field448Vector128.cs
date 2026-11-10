namespace CryptoBase.EllipticCurves.Curve448;

internal readonly struct Field448Vector128 : IField448Vector<Vector128<ulong>>
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> Create(ulong value)
	{
		return Vector128.Create(value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> Add(Vector128<ulong> left, Vector128<ulong> right)
	{
		return left + right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> Subtract(Vector128<ulong> left, Vector128<ulong> right)
	{
		return left - right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> And(Vector128<ulong> left, Vector128<ulong> right)
	{
		return left & right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> Xor(Vector128<ulong> left, Vector128<ulong> right)
	{
		return left ^ right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> ShiftRight(Vector128<ulong> value, int shift)
	{
		return value >> shift;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> MultiplyAdd(Vector128<ulong> addend, Vector128<ulong> left, Vector128<ulong> right)
	{
		return addend + Sse2.Multiply(left.AsUInt32(), right.AsUInt32());
	}
}
