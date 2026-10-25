namespace CryptoBase.EllipticCurves;

internal readonly struct LimbVector512(Vector512<ulong> value) : ILimbVector<LimbVector512>
{
	private readonly Vector512<ulong> _value = value;

	public static int Count => Vector512<ulong>.Count;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static LimbVector512 Create(ulong value)
	{
		return new LimbVector512(Vector512.Create(value));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Store(ref ulong destination)
	{
		_value.StoreUnsafe(ref destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static LimbVector512 operator +(LimbVector512 left, LimbVector512 right)
	{
		return new LimbVector512(left._value + right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static LimbVector512 MergeWhereEqual(LimbVector512 accumulator, LimbVector512 position, LimbVector512 target, ref readonly ulong source)
	{
		return new LimbVector512(Vector512.ConditionalSelect(Vector512.Equals(position._value, target._value), Vector512.LoadUnsafe(in source), accumulator._value));
	}
}
