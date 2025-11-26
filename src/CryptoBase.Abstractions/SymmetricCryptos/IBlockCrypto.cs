namespace CryptoBase.Abstractions.SymmetricCryptos;

public interface IBlockCrypto : ISymmetricCrypto
{
	/// <summary>
	/// 块大小，单位字节
	/// </summary>
	int BlockSize { get; }

	BlockCryptoHardwareAcceleration HardwareAcceleration { get; }

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
