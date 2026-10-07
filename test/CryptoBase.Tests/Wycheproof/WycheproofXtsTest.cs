using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;

namespace CryptoBase.Tests.Wycheproof;

public class WycheproofXtsTest
{
	public static IEnumerable<IndCpaTestVector> Vectors(string fileName)
	{
		return WycheproofVectors.Load<IndCpaTestVector>(fileName);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["aes_xts_test.json"])]
	public async Task AesXts(IndCpaTestVector vector)
	{
		await Assert.That(vector.Result).IsEqualTo(WycheproofResult.Valid);

		// The IV is the little-endian data unit number with its high-order zero bytes omitted.
		byte[] tweak = new byte[XtsMode<AesCipher>.TweakSize];
		vector.Iv.CopyTo(tweak, 0);
		byte[] ciphertext = new byte[vector.Msg.Length];
		byte[] plaintext = new byte[vector.Ct.Length];

		using XtsMode<AesCipher> cipher = XtsMode<AesCipher>.Create(vector.Key);
		cipher.Encrypt(tweak, vector.Msg, ciphertext);
		cipher.Decrypt(tweak, vector.Ct, plaintext);

		await Assert.That(ciphertext).IsEquivalentTo(vector.Ct, CollectionOrdering.Matching);
		await Assert.That(plaintext).IsEquivalentTo(vector.Msg, CollectionOrdering.Matching);
	}
}
