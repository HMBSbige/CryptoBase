namespace CryptoBase.Abstractions.SymmetricCryptos;

public interface IBlockModeOneShot
{
	/// <summary>
	/// 块大小，单位字节
	/// </summary>
	int BlockSize { get; }

	int GetMaxByteCount(int inputLength)
	{
		return inputLength;
	}

	void Encrypt(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> input, Span<byte> output);

	void Decrypt(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> input, Span<byte> output);
}
