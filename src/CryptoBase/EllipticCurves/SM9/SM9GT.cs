namespace CryptoBase.EllipticCurves.SM9;

// GT, the subgroup of order N of Fp12* that SM9Pairing maps onto, for the protocols of GM/T 0044.2 to 0044.4. Its elements are the values of the pairing and their products and powers; the powers take only such elements. Exponents are plain values below N.
internal static class SM9GT
{
	// The bytes of GM/T 0044.1 §7.2.6 for an element of Fp12, which the protocols hash.
	internal const int EncodedLength = SM9Fp12.ByteLength;

	internal static void Encode(in SM9Fp12 value, Span<byte> destination)
	{
		SM9Fp12.Encode(in value, destination);
	}

	// ulong.MaxValue if the elements are equal and 0 otherwise, in constant time.
	internal static ulong AreEqual(in SM9Fp12 left, in SM9Fp12 right)
	{
		return SM9Fp12.AreEqual(in left, in right);
	}

	// value^k for value in GT. Neither the time nor the addresses depend on value or k.
	internal static void Power(in SM9Fp12 value, in FieldElement<SM9Order> exponent, out SM9Fp12 result)
	{
		SM9KernelDispatch.Power(in value, in exponent, out result);
	}
}

// A base of GT with the tables of its powers that make value^k cheaper for each k, for a base used in many products, as g = e(P1, Ppub-s) is for a master public key. The base and its tables may be secret: Dispose erases them.
internal sealed class SM9GTTable : IDisposable
{
	private readonly SM9Fp12[] _table = new SM9Fp12[SM9GTPower.FixedTableLength];

	private SM9Fp12 _inverse;

	// For value in GT.
	internal SM9GTTable(in SM9Fp12 value)
	{
		SM9KernelDispatch.BuildPowerTable(in value, _table, out _inverse);
	}

	// value^k. Neither the time nor the addresses depend on the base or k.
	internal void Power(in FieldElement<SM9Order> exponent, out SM9Fp12 result)
	{
		SM9KernelDispatch.Power(_table, in _inverse, in exponent, out result);
	}

	public void Dispose()
	{
		_table.AsSpan().ZeroMemory();
		_inverse.ZeroMemory();
	}
}
