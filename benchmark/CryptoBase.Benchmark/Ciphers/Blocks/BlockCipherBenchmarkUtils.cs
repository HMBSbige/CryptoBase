using CryptoBase.Abstractions.Ciphers;

namespace CryptoBase.Benchmark.Ciphers.Blocks;

internal static class BlockCipherBenchmarkUtils
{
	public static void Transform<TCipher>(TCipher cipher, bool isDecrypt, ReadOnlySpan<byte> source, Span<byte> destination) where TCipher : IBlockCipher<TCipher>
	{
		if (isDecrypt)
		{
			cipher.DecryptBlocks(source, destination);
		}
		else
		{
			cipher.EncryptBlocks(source, destination);
		}
	}
}
