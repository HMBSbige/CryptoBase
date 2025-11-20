namespace CryptoBase.Abstractions.SymmetricCryptos;

public interface IBlockModeOneShot : ISymmetricCrypto
{
	/// <summary>
	/// 块大小，单位字节
	/// </summary>
	int BlockSize { get; }

	int GetMaxByteCount(int inputLength);

	void Encrypt(in ReadOnlySpan<byte> iv, in ReadOnlySpan<byte> input, in Span<byte> output);

	void Decrypt(in ReadOnlySpan<byte> iv, in ReadOnlySpan<byte> input, in Span<byte> output);
}
