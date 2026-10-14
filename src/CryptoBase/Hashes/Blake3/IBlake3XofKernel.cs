namespace CryptoBase.Hashes.Blake3;

internal interface IBlake3XofKernel : IBlake3Kernel
{
	static abstract void XofMany(ref readonly uint cv, ref byte block, uint blockLength, ulong counter, uint flags, nuint count, ref byte output);
}
