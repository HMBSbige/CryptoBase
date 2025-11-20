using CryptoBase.Abstractions.SymmetricCryptos;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;

public sealed class BcSm4Crypto : BlockCrypto16
{
	public override string Name => @"SM4";

	private readonly SM4Engine _encryptionEngine;
	private readonly SM4Engine _decryptionEngine;

	public BcSm4Crypto(ReadOnlySpan<byte> key)
	{
		KeyParameter keyParameter = new(key);

		_encryptionEngine = new SM4Engine();
		_decryptionEngine = new SM4Engine();
		_encryptionEngine.Init(true, keyParameter);
		_decryptionEngine.Init(false, keyParameter);
	}

	public override void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		_encryptionEngine.ProcessBlock(source, destination);
	}

	public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		_decryptionEngine.ProcessBlock(source, destination);
	}
}
