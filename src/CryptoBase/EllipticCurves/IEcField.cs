using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// The field of p for a curve with a = −3. An implementation is the storage of one element, a sequence of ulong limbs, so that points hold it directly, and its static members are the arithmetic. Multiply, Square and the inversions work in Montgomery form, Export takes and FromLimbs and TryImport give the plain value, and whether a value is in that form is otherwise up to the caller. An element need not be below p: an implementation states the form that its members take and give, and every result is in that form. No member but InvertVariableTime branches on or indexes by a value; masks are 0 or ulong.MaxValue. Any result may be the same variable as an input.
// The point formulas are members too, so that a field whose elements leave room above p can skip reductions between steps; the defaults take every step through the members here.
internal interface IEcField<TSelf> : IPrimeModulus where TSelf : unmanaged, IEcField<TSelf>
{
	// 1 in Montgomery form.
	static abstract ref readonly TSelf One { get; }

	// The element of the value of limbs, 64 bits each, least significant first, below p.
	static abstract void FromLimbs(ReadOnlySpan<ulong> limbs, out TSelf result);

	// Reads ByteLength big-endian bytes; if the value is not below p, result is 0.
	static abstract bool TryImport(ReadOnlySpan<byte> source, out TSelf result);

	// Writes the value mod p in ByteLength big-endian bytes.
	static abstract void Export(in TSelf value, Span<byte> destination);

	static abstract void Add(in TSelf left, in TSelf right, out TSelf result);

	static abstract void Subtract(in TSelf left, in TSelf right, out TSelf result);

	static abstract void Negate(in TSelf value, out TSelf result);

	static abstract void Multiply(in TSelf left, in TSelf right, out TSelf result);

	static abstract void Square(in TSelf value, out TSelf result);

	static abstract void ToMontgomery(in TSelf value, out TSelf result);

	static abstract void FromMontgomery(in TSelf value, out TSelf result);

	// 0 gives 0.
	static abstract void Invert(in TSelf value, out TSelf result);

	// The time depends on value, which must be public. 0 gives 0.
	static abstract void InvertVariableTime(in TSelf value, out TSelf result);

	// ulong.MaxValue if the value is 0 mod p and 0 otherwise.
	static abstract ulong IsZero(in TSelf value);

	static abstract ulong AreEqual(in TSelf left, in TSelf right);

	// Limb by limb, which gives an element of the form of the inputs.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static virtual void ConditionalSelect(ulong mask, in TSelf whenSet, in TSelf whenClear, out TSelf result)
	{
		Unsafe.SkipInit(out result);
		SelectLimbs(mask, ref Unsafe.As<TSelf, ulong>(ref Unsafe.AsRef(in whenSet)), ref Unsafe.As<TSelf, ulong>(ref Unsafe.AsRef(in whenClear)), ref Unsafe.As<TSelf, ulong>(ref result), Unsafe.SizeOf<TSelf>() / sizeof(ulong));
	}

	// Holds for every point: Z = 0 gives Z3 = 0, and no other point has Y = 0, as a curve of odd order has no point of order 2. The result may be the input.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static virtual void Double(in JacobianPoint<TSelf> value, out JacobianPoint<TSelf> result)
	{
		EcFormulas<TSelf>.Double(in value, out result);
	}

	// Sets result to left + right for points that are not the point at infinity, except that equal points give (0, 0, 0); opposite points give Z = 0, the point at infinity. Returns ulong.MaxValue if the points are equal, which is where H = 0 and R = 0, and 0 otherwise. The result may be either input.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static virtual ulong AddDistinct(in JacobianPoint<TSelf> left, in JacobianPoint<TSelf> right, out JacobianPoint<TSelf> result)
	{
		return EcFormulas<TSelf>.AddDistinct(in left, in right, out result);
	}

	// As above, with an affine right.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static virtual ulong AddDistinct(in JacobianPoint<TSelf> left, in AffinePoint<TSelf> right, out JacobianPoint<TSelf> result)
	{
		return EcFormulas<TSelf>.AddDistinct(in left, in right, out result);
	}
}
