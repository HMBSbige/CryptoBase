namespace CryptoBase.Hashes.Blake3;

internal interface IBlake3Compressor
{
	static abstract bool IsSupported { get; }

	static abstract void CompressBlocks(ref uint cv, ref byte blocks, nuint blockCount, ulong counter, uint flags, uint startFlags, uint endFlags);

	static abstract void Compress(ref readonly uint cv, ref byte block, uint blockLength, ulong counter, uint flags, ref byte output);

	static abstract void CompressXof(ref readonly uint cv, ref byte block, uint blockLength, ulong counter, uint flags, ref byte output);
}
