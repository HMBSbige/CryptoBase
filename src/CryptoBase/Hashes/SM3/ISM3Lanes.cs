using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Hashes.SM3;

// The vector operations of a lane kernel of SM3, which compresses Lanes messages at once: lane i of each vector belongs to message i, and vector j of a state or a block holds its word j.
internal interface ISM3Lanes<TVector> where TVector : unmanaged
{
	static abstract bool IsSupported { get; }

	static abstract int Lanes { get; }

	static abstract TVector Create(uint value);

	// start plus the index of the block that each lane writes in Store.
	static abstract TVector Counters(uint start);

	static abstract TVector Add(TVector left, TVector right);

	static abstract TVector Or(TVector left, TVector right);

	static abstract TVector Xor(TVector left, TVector right);

	static abstract TVector Xor(TVector x, TVector y, TVector z);

	// x ? y : z, bit by bit: GG of rounds 16 to 63.
	static abstract TVector Choose(TVector x, TVector y, TVector z);

	// FF of rounds 16 to 63.
	static abstract TVector Majority(TVector x, TVector y, TVector z);

	static abstract TVector RotateLeft(TVector value, [ConstantExpected(Min = 1, Max = 31)] byte count);

	static abstract TVector ShiftLeft(TVector value, int count);

	static abstract TVector ShiftRightLogical(TVector value, int count);

	static abstract TVector P0(TVector value);

	static abstract TVector P1(TVector value);

	// Writes the state words s0 to s7 of each lane as 32 big-endian bytes to the block of that lane, Lanes blocks from destination on.
	static abstract void Store(TVector s0, TVector s1, TVector s2, TVector s3, TVector s4, TVector s5, TVector s6, TVector s7, ref byte destination);
}
