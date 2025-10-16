using CryptoBase.Abstractions.SymmetricCryptos;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoBase.BouncyCastle.SymmetricCryptos.AEADCryptos;

public sealed class BcAesGcmCrypto : IAEADCrypto
{
	public string Name => @"AES-GCM";

	private readonly GcmBlockCipher _decryptionEngine;
	private readonly KeyParameter _key;
	private readonly IBlockCipher _aes;

	public BcAesGcmCrypto(ReadOnlySpan<byte> key)
	{
		_key = new KeyParameter(key);
		_aes = AesUtilities.CreateEngine();
		_decryptionEngine = new GcmBlockCipher(_aes);
	}

	public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
	{
		GcmBlockCipher engine = new(_aes);
		engine.Init(true, new AeadParameters(_key, 128, nonce.ToArray()));
		engine.AeadEncrypt(nonce, source, destination, tag, associatedData);
	}

	public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData = default)
	{
		_decryptionEngine.Init(false, new AeadParameters(_key, 128, nonce.ToArray()));
		_decryptionEngine.AeadDecrypt(nonce, source, tag, destination, associatedData);
	}

	public void Dispose() { }
}
