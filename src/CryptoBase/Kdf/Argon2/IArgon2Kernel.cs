namespace CryptoBase.Kdf.Argon2;

internal interface IArgon2Kernel
{
	static abstract bool IsSupported { get; }

	static abstract void Compress(ref Argon2Block previous, ref Argon2Block reference, ref Argon2Block destination, ref Argon2Block scratch, bool xorDestination);

	static virtual bool TryCompressChain(ref Argon2Block previous, ref Argon2Block destination, int count, Argon2ReferenceSet references, bool xorDestination)
	{
		return false;
	}
}
