using Aes = System.Security.Cryptography.Aes;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

public sealed class DefaultAesCrypto : AesCrypto
{
	private readonly Aes _aes;

	public DefaultAesCrypto(ReadOnlySpan<byte> key) : base(key)
	{
		_aes = Aes.Create();
		_aes.Key = key.ToArray();
	}

	public override void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Encrypt(source, destination);
		_aes.EncryptEcb(source.Slice(0, BlockSize), destination, PaddingMode.None);
	}

	public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Decrypt(source, destination);
		_aes.DecryptEcb(source.Slice(0, BlockSize), destination, PaddingMode.None);
	}

	public override void Dispose()
	{
		_aes.Dispose();
		base.Dispose();
	}
}
