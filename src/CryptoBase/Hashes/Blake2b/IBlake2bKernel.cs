namespace CryptoBase.Hashes.Blake2b;

internal interface IBlake2bKernel
{
	static abstract bool IsSupported { get; }

	// The first block uses counter, each following block adds 128 to it, and every block uses finalFlag.
	static abstract void Compress(ref ulong state, ReadOnlySpan<byte> blocks, UInt128 counter, ulong finalFlag);
}
