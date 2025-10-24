namespace CryptoBase.Abstractions.SymmetricCryptos;

public interface IAEADCrypto : ISymmetricCrypto
{
	void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default);

	void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData = default);
}
