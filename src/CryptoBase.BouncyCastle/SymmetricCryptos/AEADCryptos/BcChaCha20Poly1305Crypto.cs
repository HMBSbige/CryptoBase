using CryptoBase.Abstractions.SymmetricCryptos;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoBase.BouncyCastle.SymmetricCryptos.AEADCryptos;

public sealed class BcChaCha20Poly1305Crypto(ReadOnlySpan<byte> key) : IAEADCrypto
{
	public string Name => @"ChaCha20-Poly1305";

	private readonly ChaCha20Poly1305 _decryptionEngine = new();
	private readonly KeyParameter _key = new(key);

	public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
	{
		ChaCha20Poly1305 engine = new();
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
