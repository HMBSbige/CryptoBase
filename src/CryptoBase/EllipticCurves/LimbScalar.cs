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
	public void Store(ref ulong destination)
	{
		destination = _value;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static LimbScalar operator +(LimbScalar left, LimbScalar right)
	{
		return new LimbScalar(left._value + right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static LimbScalar MergeWhereEqual(LimbScalar accumulator, LimbScalar position, LimbScalar target, ref readonly ulong source)
	{
		return new LimbScalar(accumulator._value | source & LimbArithmetic.ZeroMask(position._value ^ target._value));
	}
}
