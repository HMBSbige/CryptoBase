namespace CryptoBase.EllipticCurves.SM9;

// Elements of TField, SM9Fp or SM9Fp2, in the lanes of the rows of SM9Lanes, each lane its own element, for the point formulas of SM9PointLanes. A member that takes vectors works on that many vectors of each row from vector 0; the others on vector 0. An element of Fp takes ten rows, limb l of radix 2^26 in row l, and one of Fp2 twenty, its real part in rows 0 to 9 and its u-part in rows 10 to 19. A component is reduced if limbs 0 to 8 are below 2^26 and its value is below 2.25p, as SM9Lanes has it.
// A product gives columns, twenty rows of signed columns for each component, whose values Reduce takes when they lie in [0, 400p²): Multiply gives non-negative ones, 128p² added to the real part of a product of Fp2, P0 − 2P1, and SubtractColumns adds 64p² to each component, so that sums and differences of products stay in range. None of the members branches on or indexes by a value. A result may be the same as an input, except where a member says otherwise.
internal interface ISM9FieldLanes<TField> where TField : unmanaged, ISM9Field<TField>
{
	// The ulongs of an element, of the columns of a product and of the scratch that Multiply takes.
	static abstract int ElementLength { get; }

	static abstract int ColumnsLength { get; }

	static abstract int ScratchLength { get; }

	// Lane lane of rows takes value, whose components must be reduced.
	static abstract void Split(in TField value, ref ulong rows, int lane);

	static abstract void Join(ref ulong rows, int lane, out TField result);

	// 1 in Montgomery form and 0 in every lane.
	static abstract void One(ref ulong result);

	static abstract void Clear(ref ulong result);

	// The columns of left·right for the lanes of the first vectors vectors, with the bounds that each implementation states.
	static abstract void Multiply(ref ulong left, ref ulong right, ref ulong columns, ref ulong scratch, int vectors);

	// columns − subtrahend + 64p² in columns, for columns and a subtrahend from Multiply or AddColumns.
	static abstract void SubtractColumns(ref ulong columns, ref ulong subtrahend);

	static abstract void AddColumns(ref ulong columns, ref ulong addend);

	// columns + value·2^260, which adds value to the result of Reduce, for value reduced.
	static abstract void AddShifted(ref ulong columns, ref ulong value);

	// The Montgomery reduction of columns into reduced components below 1.0001p, for values below 400p² plus at most 1.0001p·2^260 that AddShifted adds. The columns are overwritten.
	static abstract void Reduce(ref ulong columns, ref ulong result, int vectors);

	// The reduction of the product of left and right into result, as Multiply and then Reduce give it, for the first vectors vectors; columns and scratch as Multiply takes them, which this may leave unwritten.
	static abstract void MultiplyReduce(ref ulong left, ref ulong right, ref ulong result, ref ulong columns, ref ulong scratch, int vectors);

	// Two reductions side by side, for vector 0.
	static abstract void Reduce2(ref ulong columns, ref ulong otherColumns, ref ulong result, ref ulong otherResult);

	// left + right limb by limb.
	static abstract void Add(ref ulong left, ref ulong right, ref ulong result);

	// 3·value limb by limb.
	static abstract void Triple(ref ulong value, ref ulong result);

	// 3b·value, reduced, for components of value below 1.0001p with limbs 0 to 8 below 2^26: 15·value in Fp, 15u·value in Fp2. The result must not be value.
	static abstract void MultiplyByThreeB(ref ulong value, ref ulong result, int vectors);

	// value in place, from components with limbs below 2^62 and values below 2^260, to components below 1.0001p.
	static abstract void WeakReduce(ref ulong value, int vectors);

	// left + 3p − right for reduced components: values below 4.0001p and limbs below 2^27.6 for left below 1.0001p.
	static abstract void SubtractFromCover(ref ulong left, ref ulong right, ref ulong result);

	// value − first − second, reduced, for reduced components of value, first and second.
	static abstract void SubtractTwo(ref ulong value, ref ulong first, ref ulong second, ref ulong result);

	// whenSet in the lanes whose qword of mask, a row of lane masks, is all ones, and whenClear in the others.
	static abstract void ConditionalSelect(ref ulong mask, ref ulong whenSet, ref ulong whenClear, ref ulong result, int vectors);

	// value in place, negated as 3p − value in the lanes of vector 0 whose qword of mask is all ones, for reduced components: there at most 3p in limbs below 2^27.
	static abstract void ConditionalNegate(ref ulong mask, ref ulong value);

	// The operands of round 1 of the doubling of one point in lanes 0 to 2, as SM9PointLanes.DoubleSingle takes them: left = (Y, Y, Z, X) and right = (Y, Z, Z, Y), with the factor 3b of 3b·Z² in lane 2 of right where the field allows it.
	static abstract void DoublingOperands(ref ulong point, ref ulong left, ref ulong right, int vectors);

	// Lane 2 of value, reduced, times 3b where DoublingOperands left the factor out; scratch is an element.
	static abstract void ThreeBLaneTwo(ref ulong value, ref ulong scratch, int vectors);

	// Lane i takes lane i + distance of value for every lane i of vector 0 whose lane i + distance is in vector 0, distance 1, 2 or 4; the other lanes take lanes of value. The result must not be value.
	static abstract void MoveDown(ref ulong value, int distance, ref ulong result);
}
