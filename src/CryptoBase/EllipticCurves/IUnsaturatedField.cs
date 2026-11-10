namespace CryptoBase.EllipticCurves;

// An IECField whose elements hold the value in limbs of fewer than 64 bits: TryImport, Export and the inversions go through the FieldElement of TModulus, as SafeGcd works on the canonical value in 64-bit limbs.
internal interface IUnsaturatedField<TSelf, TModulus> : IECField<TSelf> where TSelf : unmanaged, IUnsaturatedField<TSelf, TModulus> where TModulus : unmanaged, IMontgomeryModulus
{
	// The numerator for SafeGcd that takes aR to a⁻¹R.
	static abstract ReadOnlySpan<ulong> InverseNumerator { get; }

	// The value mod p in 64-bit limbs.
	static abstract void ToSaturated(in TSelf value, out FieldElement<TModulus> result);

	static bool IECField<TSelf>.TryImport(ReadOnlySpan<byte> source, out TSelf result)
	{
		bool valid = FieldElement<TModulus>.TryImport(source, out FieldElement<TModulus> value);
		TSelf.FromLimbs(FieldElement<TModulus>.GetLimbs(in value), out result);
		return valid;
	}

	static void IECField<TSelf>.Export(in TSelf value, Span<byte> destination)
	{
		TSelf.ToSaturated(in value, out FieldElement<TModulus> saturated);
		FieldElement<TModulus>.Export(in saturated, destination);
		saturated.ZeroMemory();
	}

	static void IECField<TSelf>.Invert(in TSelf value, out TSelf result)
	{
		TSelf.ToSaturated(in value, out FieldElement<TModulus> saturated);
		SafeGcd<TModulus>.Invert(in saturated, TSelf.InverseNumerator, out saturated);
		TSelf.FromLimbs(FieldElement<TModulus>.GetLimbs(in saturated), out result);
		saturated.ZeroMemory();
	}

	static void IECField<TSelf>.InvertVariableTime(in TSelf value, out TSelf result)
	{
		TSelf.ToSaturated(in value, out FieldElement<TModulus> saturated);
		SafeGcd<TModulus>.InvertVariableTime(in saturated, TSelf.InverseNumerator, out saturated);
		TSelf.FromLimbs(FieldElement<TModulus>.GetLimbs(in saturated), out result);
	}
}
