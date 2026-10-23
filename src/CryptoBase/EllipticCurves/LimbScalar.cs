namespace CryptoBase.EllipticCurves;

internal readonly struct LimbScalar(ulong value) : ILimbVector<LimbScalar>
{
	private readonly ulong _value = value;

	public static int Count => 1;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static LimbScalar Create(ulong value)
	{
		return new LimbScalar(value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static LimbScalar Load(ref readonly ulong source)
	{
		return new LimbScalar(source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Store(ref ulong destination)
	{
		destination = _value;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static LimbScalar Equal(LimbScalar left, LimbScalar right)
	{
		return new LimbScalar(LimbArithmetic.ZeroMask(left._value ^ right._value));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static LimbScalar operator +(LimbScalar left, LimbScalar right)
	{
		return new LimbScalar(left._value + right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static LimbScalar operator &(LimbScalar left, LimbScalar right)
	{
		return new LimbScalar(left._value & right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static LimbScalar operator |(LimbScalar left, LimbScalar right)
	{
		return new LimbScalar(left._value | right._value);
	}
}
