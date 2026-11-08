namespace CryptoBase.EllipticCurves.SM9;

// The field of an SM9 curve with the arithmetic that SM9Curve takes, on reduced elements in Montgomery form: SM9Fp for E: y² = x³ + 5, which holds G1, and SM9Fp2 for the twist E': y² = x³ + 5u, which holds G2. No member but InvertVariableTime branches on or indexes by a value; masks are 0 or ulong.MaxValue. Any result may be the same variable as an input.
internal interface ISM9Field<TSelf> where TSelf : unmanaged, ISM9Field<TSelf>
{
	static abstract ref readonly TSelf One { get; }

	// The coefficient b of the curve over this field, in Montgomery form.
	static abstract ref readonly TSelf B { get; }

	static abstract void Multiply(in TSelf left, in TSelf right, out TSelf result);

	static abstract void Square(in TSelf value, out TSelf result);

	static abstract void Add(in TSelf left, in TSelf right, out TSelf result);

	static abstract void Subtract(in TSelf left, in TSelf right, out TSelf result);

	static abstract void Negate(in TSelf value, out TSelf result);

	// value·k for k up to 9.
	static abstract void MultiplySmall(in TSelf value, uint k, out TSelf result);

	// value·3b.
	static abstract void MultiplyByThreeB(in TSelf value, out TSelf result);

	static abstract ulong IsZero(in TSelf value);

	static abstract ulong AreEqual(in TSelf left, in TSelf right);

	static abstract void ConditionalSelect(ulong mask, in TSelf whenSet, in TSelf whenClear, out TSelf result);

	// 0 gives 0.
	static abstract void Invert(in TSelf value, out TSelf result);

	// The time depends on value, which must be public. 0 gives 0.
	static abstract void InvertVariableTime(in TSelf value, out TSelf result);
}
