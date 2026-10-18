namespace CryptoBase.Kdf.Argon2;

internal interface IArgon2Kernel
{
	static abstract bool IsSupported { get; }

	static abstract void Compress(ref Argon2Block previous, ref Argon2Block reference, ref Argon2Block destination, ref Argon2Block scratch, bool xorDestination);

	// Computes the blocks of a data-dependent segment from startIndex on, or returns false to leave them to the caller; segment is the first block of the segment, and previous the block before the one at startIndex.
	static virtual bool TryCompressChain(ref Argon2Block previous, ref Argon2Block segment, int startIndex, int segmentLength, Argon2ReferenceSet references, bool xorDestination)
	{
		return false;
	}
}
