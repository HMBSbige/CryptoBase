namespace CryptoBase.EllipticCurves;

// A curve field in the saturated limbs of FieldElement: TSelf is the modulus and the storage of an element at once, as FieldElement<TSelf> holds nothing else, and every member of IEcField goes to FieldElement<TSelf>, so that an element is always below p.
internal interface ISaturatedField<TSelf> : IMontgomeryModulus, IEcField<TSelf> where TSelf : unmanaged, ISaturatedField<TSelf>
{
	static ref readonly TSelf IEcField<TSelf>.One => ref Unsafe.As<FieldElement<TSelf>, TSelf>(ref Unsafe.AsRef(in FieldElement<TSelf>.MontgomeryOne));

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static void IEcField<TSelf>.FromLimbs(ReadOnlySpan<ulong> limbs, out TSelf result)
	{
		result = Unsafe.As<FieldElement<TSelf>, TSelf>(ref Unsafe.AsRef(in FieldElement<TSelf>.FromLimbs(limbs)));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static bool IEcField<TSelf>.TryImport(ReadOnlySpan<byte> source, out TSelf result)
	{
		Unsafe.SkipInit(out result);
		return FieldElement<TSelf>.TryImport(source, out Element(ref result));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static void IEcField<TSelf>.Export(in TSelf value, Span<byte> destination)
	{
		FieldElement<TSelf>.Export(in Element(in value), destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static void IEcField<TSelf>.Add(in TSelf left, in TSelf right, out TSelf result)
	{
		Unsafe.SkipInit(out result);
		FieldElement<TSelf>.Add(in Element(in left), in Element(in right), out Element(ref result));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static void IEcField<TSelf>.Subtract(in TSelf left, in TSelf right, out TSelf result)
	{
		Unsafe.SkipInit(out result);
		FieldElement<TSelf>.Subtract(in Element(in left), in Element(in right), out Element(ref result));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static void IEcField<TSelf>.Negate(in TSelf value, out TSelf result)
	{
		Unsafe.SkipInit(out result);
		FieldElement<TSelf>.Negate(in Element(in value), out Element(ref result));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static void IEcField<TSelf>.Multiply(in TSelf left, in TSelf right, out TSelf result)
	{
		Unsafe.SkipInit(out result);
		FieldElement<TSelf>.Multiply(in Element(in left), in Element(in right), out Element(ref result));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static void IEcField<TSelf>.Square(in TSelf value, out TSelf result)
	{
		Unsafe.SkipInit(out result);
		FieldElement<TSelf>.Square(in Element(in value), out Element(ref result));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static void IEcField<TSelf>.ToMontgomery(in TSelf value, out TSelf result)
	{
		Unsafe.SkipInit(out result);
		FieldElement<TSelf>.ToMontgomery(in Element(in value), out Element(ref result));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static void IEcField<TSelf>.FromMontgomery(in TSelf value, out TSelf result)
	{
		Unsafe.SkipInit(out result);
		FieldElement<TSelf>.FromMontgomery(in Element(in value), out Element(ref result));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static void IEcField<TSelf>.Invert(in TSelf value, out TSelf result)
	{
		Unsafe.SkipInit(out result);
		FieldElement<TSelf>.Invert(in Element(in value), out Element(ref result));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static void IEcField<TSelf>.InvertVariableTime(in TSelf value, out TSelf result)
	{
		Unsafe.SkipInit(out result);
		FieldElement<TSelf>.InvertVariableTime(in Element(in value), out Element(ref result));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static ulong IEcField<TSelf>.IsZero(in TSelf value)
	{
		return FieldElement<TSelf>.IsZero(in Element(in value));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static ulong IEcField<TSelf>.AreEqual(in TSelf left, in TSelf right)
	{
		return FieldElement<TSelf>.AreEqual(in Element(in left), in Element(in right));
	}

	// The element that value holds, which may be written only through a ref to a writable variable.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ref FieldElement<TSelf> Element(ref readonly TSelf value)
	{
		return ref Unsafe.As<TSelf, FieldElement<TSelf>>(ref Unsafe.AsRef(in value));
	}
}
