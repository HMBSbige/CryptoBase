using CryptoBase.Abstractions.SymmetricCryptos;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;

public sealed class BcAesCrypto : BlockCryptoBase
{
	public override string Name => @"AES";

	public override int BlockSize => 16;

	private readonly IBlockCipher _encryptionEngine;
	private readonly IBlockCipher _decryptionEngine;

	public BcAesCrypto(ReadOnlySpan<byte> key)
	{
		KeyParameter keyParameter = new(key);

		_encryptionEngine = AesUtilities.CreateEngine();
		_decryptionEngine = AesUtilities.CreateEngine();
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
