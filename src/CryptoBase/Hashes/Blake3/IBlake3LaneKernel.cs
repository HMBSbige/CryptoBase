namespace CryptoBase.Hashes.Blake3;

internal interface IBlake3LaneKernel : IBlake3Kernel
{
	static abstract void Hash(ref byte input, nuint count, nuint tailBlocks, ref readonly uint key, ulong counter, uint flags, ref byte output);
}
