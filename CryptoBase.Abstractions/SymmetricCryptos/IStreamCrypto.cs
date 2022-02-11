namespace CryptoBase.Abstractions.SymmetricCryptos;

public interface IStreamCrypto : ISymmetricCrypto, ICanReset
{
	/// <summary>
	/// 加密/解密
	/// </summary>
	void Update(ReadOnlySpan<byte> source, Span<byte> destination);
}
