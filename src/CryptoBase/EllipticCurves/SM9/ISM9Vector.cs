namespace CryptoBase.EllipticCurves.SM9;

// The lane arithmetic of the vector kernels of SM9, on Count lanes of 64 bits each. A lane holds a limb of radix 2^26 or a column of a product, which the reductions read as signed; Multiply takes the low 32 bits of each lane, as vpmuludq and umull do. None branches on or indexes by a value.
internal interface ISM9Vector<TSelf> where TSelf : unmanaged, ISM9Vector<TSelf>
{
	static abstract bool IsSupported { get; }

	static abstract int Count { get; }

	// The number of vector registers, which chooses the kernels: with 32 the sums of a product stay in registers, with 16 they go through memory.
	static abstract int RegisterCount { get; }

	static abstract TSelf Zero { get; }

	static abstract TSelf Create(ulong value);

	static abstract TSelf Load(ref readonly ulong source);

	static abstract TSelf LoadBroadcast(ref readonly ulong source);

	// The two values at source in every pair of lanes. source must be in memory that does not move, as the stack and native memory, which hold every lane the kernels take.
	static abstract TSelf LoadPairBroadcast(ref readonly ulong source);

	void Store(ref ulong destination);

	static abstract TSelf operator +(TSelf left, TSelf right);

	static abstract TSelf operator -(TSelf left, TSelf right);

	static abstract TSelf operator &(TSelf left, TSelf right);

	static abstract TSelf operator |(TSelf left, TSelf right);

	static abstract TSelf operator <<(TSelf value, int shift);

	static abstract TSelf operator >>>(TSelf value, int shift);

	// The low 32 bits of each lane of left times those of right, a 64-bit product.
	static abstract TSelf Multiply(TSelf left, TSelf right);

	// addend + Multiply(left, right), which some instruction sets take in one instruction.
	static abstract TSelf MultiplyAdd(TSelf addend, TSelf left, TSelf right);

	// Multiply(left, Create(factor)) and MultiplyAdd(addend, left, Create(factor)) for a constant factor, which an instruction set whose products take narrowed operands takes as it is.
	static abstract TSelf MultiplyByFactor(TSelf left, uint factor);

	static abstract TSelf MultiplyAddByFactor(TSelf addend, TSelf left, uint factor);

	// ⌊value/2^26⌋ for each lane read as signed.
	static abstract TSelf ShiftRightArithmetic26(TSelf value);

	// whenSet where mask is all ones and whenClear where it is 0, lane by lane.
	static abstract TSelf ConditionalSelect(TSelf mask, TSelf whenSet, TSelf whenClear);

	// The row of eight lanes at destination whose lane j is lane n_j of the sixteen lanes of the rows at first and second, n_j in bits 4j to 4j + 3 of pattern, which is a constant. destination may be first or second.
	static abstract void Permute(ref readonly ulong first, ref readonly ulong second, ref ulong destination, ulong pattern);

	// As above, writing every lane of the destination row, padding included.
	static abstract void PermuteFull(ref readonly ulong first, ref readonly ulong second, ref ulong destination, ulong pattern);

	// As above in registers, for a type whose Count is the eight lanes of a row; the kernels take it only for such a type.
	static abstract TSelf Permute(TSelf first, TSelf second, ulong pattern);
}
