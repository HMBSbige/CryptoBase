namespace CryptoBase.Abstractions.SymmetricCryptos;

[Obsolete]
public interface IBlockCrypto : ISymmetricCrypto
{
	void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination);

	void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination);

	void Encrypt2(ReadOnlySpan<byte> source, Span<byte> destination);

	void Decrypt2(ReadOnlySpan<byte> source, Span<byte> destination);

	void Encrypt4(ReadOnlySpan<byte> source, Span<byte> destination);

	void Decrypt4(ReadOnlySpan<byte> source, Span<byte> destination);

	void Encrypt8(ReadOnlySpan<byte> source, Span<byte> destination);

	void Decrypt8(ReadOnlySpan<byte> source, Span<byte> destination);

	void Encrypt16(ReadOnlySpan<byte> source, Span<byte> destination);

	void Decrypt16(ReadOnlySpan<byte> source, Span<byte> destination);

	void Encrypt32(ReadOnlySpan<byte> source, Span<byte> destination);

	void Decrypt32(ReadOnlySpan<byte> source, Span<byte> destination);
}
