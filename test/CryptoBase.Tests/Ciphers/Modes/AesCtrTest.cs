using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Modes;

public class AesCtrTest
{
	/// <summary>
	/// NIST SP 800-38A, AES-128 CTR example.
	/// </summary>
	[Test]
	public async Task StandardVector()
	{
		byte[] key = Convert.FromHexString("2B7E151628AED2A6ABF7158809CF4F3C");
		byte[] counter = Convert.FromHexString("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");
		byte[] plaintext = Convert.FromHexString("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710");
		byte[] ciphertext = Convert.FromHexString("874D6191B620E3261BEF6864990DB6CE9806F66B7970FDFF8617187BB9FFFDFF5AE4DF3EDBD5D35E5B4F09020DB03EAB1E031DDA2FBE03D1792170A0F3009CEE");

		await VerifyStreamVector(CtrMode128<AesCipher>.Create(key, counter), plaintext, ciphertext);
	}

	/// <summary>
	/// RFC 3711 Appendix B.2, SRTP AES-CM keystream for one packet IV.
	/// </summary>
	[Test]
	public async Task SrtpKeystreamVectorAfterReset()
	{
		byte[] key = Convert.FromHexString("2B7E151628AED2A6ABF7158809CF4F3C");
		byte[] iv = Convert.FromHexString("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000");
		byte[] head = Convert.FromHexString("E03EAD0935C95E80E166B16DD92B4EB4D23513162B02D0F72A43A2FE4A5F97AB41E95B3BB0A2E8DD477901E4FCA894C0");
		byte[] tail = Convert.FromHexString("EC8CDF7398607CB0F2D21675EA9EA1E4362B7C3C6773516318A077D7FC5073AE6A2CC3787889374FBEB4C81B17BA6C44");
		byte[] keyStream = new byte[1044512];

		using CtrMode128<AesCipher> cipher = CtrMode128<AesCipher>.Create(key, new byte[16]);
		// Leave unused keystream from a partial block for Reset to discard.
		cipher.Xor(new byte[5], new byte[5]);
		cipher.Reset(iv);
		cipher.Xor(keyStream, keyStream);

		await Assert.That(keyStream.AsMemory(0, head.Length)).IsEquivalentTo(head, CollectionOrdering.Matching);
		await Assert.That(keyStream.AsMemory(keyStream.Length - tail.Length)).IsEquivalentTo(tail, CollectionOrdering.Matching);
	}
}
