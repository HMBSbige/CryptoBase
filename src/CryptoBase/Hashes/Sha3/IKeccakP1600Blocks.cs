namespace CryptoBase.Hashes.Sha3;

// What KeccakP1600Interleaved.Permute does with the blocks of a single state's input or output: XOR the rate lanes of each block into the state before a permutation, or write them to the block after one, so that the lanes stay in registers from block to block.
internal interface IKeccakP1600Blocks
{
	static abstract bool Absorbs { get; }

	static abstract bool Squeezes { get; }

	static abstract int RateInBytes { get; }
}
