namespace CryptoBase.Hashes.Sha3;

// Keccak-p[1600, 24] on Lanes independent states at once. The states are interleaved lane by lane: word Lanes * i + j holds lane i = x + 5y of state j, so lane i of every state is one vector, and the whole batch is 25 * Lanes words.
internal interface IKeccakP1600Kernel
{
	static abstract bool IsSupported { get; }

	static abstract int Lanes { get; }

	static abstract void Permute(ref ulong state);
}
