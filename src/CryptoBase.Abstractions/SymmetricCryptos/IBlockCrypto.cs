namespace CryptoBase.Abstractions.SymmetricCryptos;

public interface IBlockCrypto : ISymmetricCrypto
{
	/// <summary>
	/// 块大小，单位字节
	/// </summary>
	int BlockSize { get; }

	/// <summary>
	/// 加密
	/// </summary>
	void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination);

	/// <summary>
	/// 解密
	/// </summary>
	void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination);
}
