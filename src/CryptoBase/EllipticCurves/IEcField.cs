using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// The field of p for a curve with a = −3. An implementation is the storage of one element, a sequence of ulong limbs, so that points hold it directly, and its static members are the arithmetic. Multiply, Square and the inversions work in Montgomery form, Export takes and FromLimbs and TryImport give the plain value, and whether a value is in that form is otherwise up to the caller. An element need not be below p: an implementation states the form that its members take and give, and every result but those of AddUnreduced and SubtractUnreduced is in that form. No member but InvertVariableTime branches on or indexes by a value; masks are 0 or ulong.MaxValue. Any result may be the same variable as an input.
// The point formulas are members too, so that a field can choose where to reduce between steps; the defaults, in EcFormulas, reduce only where WeakReduce is called, and a field that takes them states the bounds that keep each step within what the next one takes.
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

	static abstract void Multiply(in TSelf left, in TSelf right, out TSelf result);

	static abstract void Square(in TSelf value, out TSelf result);

	static abstract void ToMontgomery(in TSelf value, out TSelf result);

	static abstract void FromMontgomery(in TSelf value, out TSelf result);

	// 0 gives 0.
	static abstract void Invert(in TSelf value, out TSelf result);

	// The time depends on value, which must be public. 0 gives 0.
	static abstract void InvertVariableTime(in TSelf value, out TSelf result);

	// Limb by limb without carries; the caller keeps the result within what the next operation takes.
	static abstract void AddUnreduced(in TSelf left, in TSelf right, out TSelf result);

	// left + kp − right limb by limb, for a right of the form and a multiple kp of p whose limbs cover those of the form, so that no limb goes negative.
	static abstract void SubtractUnreduced(in TSelf left, in TSelf right, out TSelf result);

	// Carries the limbs back into the form, with a value below 2p.
	static abstract void WeakReduce(in TSelf value, out TSelf result);

	// For an output of WeakReduce: ulong.MaxValue if it is 0 mod p, which below 2p means 0 or p, and 0 otherwise.
	static abstract ulong IsReducedZero(in TSelf value);

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static virtual void Add(in TSelf left, in TSelf right, out TSelf result)
	{
		TSelf.AddUnreduced(in left, in right, out result);
		TSelf.WeakReduce(in result, out result);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static virtual void Subtract(in TSelf left, in TSelf right, out TSelf result)
	{
		TSelf.SubtractUnreduced(in left, in right, out result);
		TSelf.WeakReduce(in result, out result);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static virtual void Negate(in TSelf value, out TSelf result)
	{
		TSelf zero = default;
		TSelf.Subtract(in zero, in value, out result);
	}

	// ulong.MaxValue if the value is 0 mod p and 0 otherwise.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static virtual ulong IsZero(in TSelf value)
	{
		TSelf.WeakReduce(in value, out TSelf reduced);
		return TSelf.IsReducedZero(in reduced);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static virtual ulong AreEqual(in TSelf left, in TSelf right)
	{
		TSelf.SubtractUnreduced(in left, in right, out TSelf difference);
		return TSelf.IsZero(in difference);
	}

	// Limb by limb, which gives an element of the form of the inputs.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static virtual void ConditionalSelect(ulong mask, in TSelf whenSet, in TSelf whenClear, out TSelf result)
	{
		Unsafe.SkipInit(out result);
		SelectLimbs(mask, ref Unsafe.As<TSelf, ulong>(ref Unsafe.AsRef(in whenSet)), ref Unsafe.As<TSelf, ulong>(ref Unsafe.AsRef(in whenClear)), ref Unsafe.As<TSelf, ulong>(ref result), Unsafe.SizeOf<TSelf>() / sizeof(ulong));
	}

	// The limbs of each coordinate in EcGeneratorTable: by default those of the element, but a field whose elements leave room above p may pack the value mod p into fewer.
	static virtual int PackedLength => Unsafe.SizeOf<TSelf>() / sizeof(ulong);

	// Writes X and then Y of point in PackedLength limbs each.
	static virtual void Pack(in AffinePoint<TSelf> point, Span<ulong> destination)
	{
		MemoryMarshal.Cast<AffinePoint<TSelf>, ulong>(new ReadOnlySpan<AffinePoint<TSelf>>(in point)).CopyTo(destination);
	}

	// Turns the limbs that Pack wrote, at the start of point, back into elements in place.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static virtual void Unpack(ref AffinePoint<TSelf> point)
	{
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
