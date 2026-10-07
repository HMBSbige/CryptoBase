using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Aead;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes;
using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Tests.Wycheproof;

public class WycheproofAeadTest
{
	public static IEnumerable<AeadTestVector> Vectors(string fileName)
	{
		return WycheproofVectors.Load<AeadTestVector>(fileName);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["aes_gcm_test.json"])]
	public Task AesGcm(AeadTestVector vector)
	{
		return Verify<GcmMode128<AesCipher>>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["aes_ccm_test.json"])]
	public Task AesCcm(AeadTestVector vector)
	{
		return Verify<CcmMode128<AesCipher>>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["aes_ccm_test.json"])]
	public Task AesCcm8(AeadTestVector vector)
	{
		return Verify<Ccm8Mode128<AesCipher>>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["sm4_gcm_test.json"])]
	public Task SM4Gcm(AeadTestVector vector)
	{
		return Verify<GcmMode128<SM4Cipher>>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["sm4_ccm_test.json"])]
	public Task SM4Ccm(AeadTestVector vector)
	{
		return Verify<CcmMode128<SM4Cipher>>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["sm4_ccm_test.json"])]
	public Task SM4Ccm8(AeadTestVector vector)
	{
		return Verify<Ccm8Mode128<SM4Cipher>>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["chacha20_poly1305_test.json"])]
	public Task ChaCha20Poly1305(AeadTestVector vector)
	{
		return Verify<ChaCha20Poly1305Cipher>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["xchacha20_poly1305_test.json"])]
	public Task XChaCha20Poly1305(AeadTestVector vector)
	{
		return Verify<XChaCha20Poly1305Cipher>(vector);
	}

	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before the cipher is disposed.")]
	private static async Task Verify<T>(AeadTestVector vector) where T : IAeadCipher<T>
	{
		using T cipher = T.Create(vector.Key);
		byte[] ciphertext = new byte[vector.Msg.Length];
		byte[] tag = new byte[vector.Tag.Length];
		byte[] plaintext = new byte[vector.Ct.Length];

		// The files also cover nonce and tag sizes that a cipher does not offer; valid or not, it must reject them.
		if (vector.Iv.Length != T.NonceSize || vector.Tag.Length != T.TagSize)
		{
			await Assert.That(() => cipher.Encrypt(vector.Iv, vector.Msg, ciphertext, tag, vector.Aad)).Throws<ArgumentException>();
			await Assert.That(() => cipher.TryDecrypt(vector.Iv, vector.Ct, vector.Tag, plaintext, vector.Aad)).Throws<ArgumentException>();
			return;
		}

		if (vector.Result is WycheproofResult.Invalid)
		{
			await Assert.That(cipher.TryDecrypt(vector.Iv, vector.Ct, vector.Tag, plaintext, vector.Aad)).IsFalse();
			return;
		}

		cipher.Encrypt(vector.Iv, vector.Msg, ciphertext, tag, vector.Aad);
		await Assert.That(ciphertext).IsEquivalentTo(vector.Ct, CollectionOrdering.Matching);
		await Assert.That(tag).IsEquivalentTo(vector.Tag, CollectionOrdering.Matching);
		await Assert.That(cipher.TryDecrypt(vector.Iv, vector.Ct, vector.Tag, plaintext, vector.Aad)).IsTrue();
		await Assert.That(plaintext).IsEquivalentTo(vector.Msg, CollectionOrdering.Matching);
	}
}
