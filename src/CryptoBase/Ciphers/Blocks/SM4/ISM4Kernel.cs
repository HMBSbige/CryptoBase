namespace CryptoBase.Ciphers.Blocks.SM4;

internal interface ISM4Kernel
{
	static abstract bool IsSupported { get; }

	// Supported maximum widths are 4, 8, 16, 32 and 64 blocks.
	static abstract int MaxBlocks { get; }

	// width is a power of two in [4, MaxBlocks]; count is in [1, width].
	// Read and write exactly count blocks. Exact in-place operation is supported.
	static abstract void Process(int width, int count, ref uint rk, ref byte source, ref byte destination);
}
