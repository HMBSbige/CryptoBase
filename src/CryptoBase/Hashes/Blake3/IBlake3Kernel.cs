namespace CryptoBase.Hashes.Blake3;

internal interface IBlake3Kernel
{
	static abstract bool IsSupported { get; }

	static abstract int Degree { get; }

	static abstract void HashChunks(ref byte input, nuint length, ref readonly uint key, ulong counter, uint flags, ref byte output);

	static abstract void HashParents(ref byte input, nuint count, ref readonly uint key, uint flags, ref byte output);
}
