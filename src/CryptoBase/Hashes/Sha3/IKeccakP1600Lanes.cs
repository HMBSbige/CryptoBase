namespace CryptoBase.Hashes.Sha3;

// The lane-wise operations of a round on vectors that each hold the same lane of several interleaved states,
// so that KeccakP1600Interleaved spells the round once for every vector width.
internal interface IKeccakP1600Lanes<TVector> where TVector : struct
{
	static abstract TVector Xor(TVector left, TVector right);

	static abstract TVector Xor5(TVector a, TVector b, TVector c, TVector d, TVector e);

	// χ: value ^ (~left & right).
	static abstract TVector XorAndNot(TVector value, TVector left, TVector right);

	static abstract TVector RotateLeft(TVector value, byte offset);

	static abstract TVector Create(ulong value);
}
