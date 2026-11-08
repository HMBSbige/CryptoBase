namespace CryptoBase.EllipticCurves;

// LaneCount elements of the field of p, one in each lane, as SM2Field29 describes them, with the bounds stated there. A lane mask is LaneCount consecutive ulongs, each 0 or ulong.MaxValue, so that the scalar code that derives masks from digits writes them as it goes. None of the members branches on or indexes by a value, and any result may be the same variable as an input.
internal interface ISM2Field29Lanes<TSelf> where TSelf : unmanaged, ISM2Field29Lanes<TSelf>
{
	static abstract bool IsSupported { get; }

	static abstract int LaneCount { get; }

	// 1 in Montgomery form in every lane.
	static abstract void One(out TSelf result);

	static abstract void Multiply(in TSelf left, in TSelf right, out TSelf result);

	static abstract void Square(in TSelf value, out TSelf result);

	// As Multiply and Square, the same values with every limb but limb 8 below 2^29, for products that need not wait for each other, as RippleCarry describes.
	static abstract void MultiplyRipple(in TSelf left, in TSelf right, out TSelf result);

	static abstract void SquareRipple(in TSelf value, out TSelf result);

	static abstract void Add(in TSelf left, in TSelf right, out TSelf result);

	// left + 4p − right.
	static abstract void Subtract(in TSelf left, in TSelf right, out TSelf result);

	static abstract void Reduce(in TSelf value, out TSelf result);

	static abstract void ConditionalSelect(ref readonly ulong mask, in TSelf whenSet, in TSelf whenClear, out TSelf result);

	// 4p − value where mask is set, for a value whose limbs are at most those of the 4p of SM2Field29.
	static abstract void ConditionalNegate(ref readonly ulong mask, ref TSelf value);

	// Lane i takes lane i + distance for each i whose bit of distance is clear, distance a power of two below LaneCount; the other lanes take any values.
	static abstract void MoveDown(in TSelf value, int distance, out TSelf result);

	// The coordinates of LaneCount affine points as SM2Field52.Pack writes them, point i at Unsafe.Add(ref entries, 8i), in lane i: each value v below p as 2v, in limbs below 2^29, limb 8 below 2^25.
	static abstract void LoadEntries(ref readonly ulong entries, out TSelf x, out TSelf y);

	// value/2 mod p, for limbs below 2^63, as SM2Field29 describes it, for Reduce: it takes an element of the lanes, a·2^261, to the a·2^260 of SM2Field52, whose limbs SM2Field29.ToField52 joins.
	static abstract void Halve(in TSelf value, out TSelf result);
}
