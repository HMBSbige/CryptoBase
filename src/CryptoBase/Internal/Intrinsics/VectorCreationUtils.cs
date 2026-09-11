namespace CryptoBase.Internal.Intrinsics;

internal static class VectorCreationUtils
{
	/// <summary>
	/// Vector128.Create(a, x, b, x)
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> CreateTwoUInt(uint a, uint b)
	{
		if (Sse2.IsSupported)
		{
			Vector128<uint> t1 = Vector128.CreateScalarUnsafe(a);
			Vector128<uint> t2 = Vector128.CreateScalarUnsafe(b);

			return Sse2.UnpackLow(t1.AsUInt64(), t2.AsUInt64()).AsUInt32();
		}

		return Vector128.Create(a, 0, b, 0);
	}

	/// <summary>
	/// Vector256.Create(a, 0, b, 0, c, 0, d, 0)
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<uint> Create4UInt(uint a, uint b, uint c, uint d)
	{
		return Vector256.Create(Vector128.CreateScalar(a).WithElement(2, b), Vector128.CreateScalar(c).WithElement(2, d));
	}
}
