using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.AeadCryptos;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.SymmetricCryptos.AeadCryptos;

public class AeadContractTest
{
	[Test]
	[Arguments(FailureAeadAlgorithm.DefaultAesGcm, 73)]
	[Arguments(FailureAeadAlgorithm.DefaultAesGcm, 257)]
	[Arguments(FailureAeadAlgorithm.DefaultChaCha20Poly1305, 73)]
	[Arguments(FailureAeadAlgorithm.DefaultChaCha20Poly1305, 257)]
	[Arguments(FailureAeadAlgorithm.ChaCha20Poly1305, 73)]
	[Arguments(FailureAeadAlgorithm.ChaCha20Poly1305, 257)]
	[Arguments(FailureAeadAlgorithm.XChaCha20Poly1305, 73)]
	[Arguments(FailureAeadAlgorithm.XChaCha20Poly1305, 257)]
	public async Task AuthenticationFailureDoesNotModifyDestination(FailureAeadAlgorithm algorithm, int plaintextSizeInBytes)
	{
		byte[] key = CreateDeterministicSource(32);
		using IAeadCrypto crypto = CreateFailureCrypto(algorithm, key);
		byte[] nonce = CreateDeterministicSource(crypto.NonceSizeInBytes);
		byte[] associatedData = CreateDeterministicSource(19);
		byte[] plaintext = CreateDeterministicSource(plaintextSizeInBytes);
		byte[] ciphertext = new byte[crypto.GetCiphertextSizeInBytes(plaintext.Length)];
		byte[] tag = new byte[crypto.TagSizeInBytes];
		crypto.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

		byte[] invalidTag = tag.ToArray();
		invalidTag[0] ^= 1;
		byte[] destination = new byte[crypto.GetPlaintextSizeInBytes(ciphertext.Length)];
		PrepareDestination(destination);

		// ReSharper disable once AccessToDisposedClosure
		await Assert.That(() => crypto.Decrypt(nonce, ciphertext, invalidTag, destination, associatedData))
			.ThrowsExactly<AuthenticationTagMismatchException>();

		await Assert.That(destination).All(static value => value is DestinationSentinel);

		crypto.Decrypt(nonce, ciphertext, tag, destination, associatedData);
		await Assert.That(destination).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
	}

	private static IAeadCrypto CreateFailureCrypto(FailureAeadAlgorithm algorithm, ReadOnlySpan<byte> key)
	{
		return algorithm switch
		{
			FailureAeadAlgorithm.DefaultAesGcm => new DefaultAesGcmCrypto(key),
			FailureAeadAlgorithm.DefaultChaCha20Poly1305 => new DefaultChaCha20Poly1305Crypto(key),
			FailureAeadAlgorithm.ChaCha20Poly1305 => new ChaCha20Poly1305Crypto(key),
			FailureAeadAlgorithm.XChaCha20Poly1305 => new XChaCha20Poly1305Crypto(key),
			_ => throw new ArgumentOutOfRangeException(nameof(algorithm))
		};
	}

	public enum FailureAeadAlgorithm
	{
		DefaultAesGcm,
		DefaultChaCha20Poly1305,
		ChaCha20Poly1305,
		XChaCha20Poly1305
	}
}
