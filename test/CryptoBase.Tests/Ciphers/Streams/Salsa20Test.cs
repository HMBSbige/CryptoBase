using CryptoBase.Ciphers.Streams;

namespace CryptoBase.Tests.Ciphers.Streams;

public class Salsa20Test
{
	[Test]
	[Arguments
	(
		"0053A6F94C9FF24598EB3E91E4378ADD",
		"0D74DB42A91077DE",
		"05E1E7BEB697D999656BF37C1B978806735D0B903A6007BD329927EFBE1B0E2A8137C1AE291493AA83A821755BEE0B06CD14855A67E46703EBF8F3114B584CBA"
	)]
	[Arguments
	(
		"0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D",
		"0D74DB42A91077DE",
		"F5FAD53F79F9DF58C4AEA0D0ED9A9601F278112CA7180D565B420A48019670EAF24CE493A86263F677B46ACE1924773D2BB25571E1AA8593758FC382B1280B71"
	)]
	public async Task VerifiedFirstBlockForBothKeySizes(string keyHex, string nonceHex, string expectedHex)
	{
		byte[] expected = Convert.FromHexString(expectedHex);
		byte[] source = new byte[64];
		byte[] actual = new byte[source.Length];
		using Salsa20Cipher crypto = new(Convert.FromHexString(keyHex), Convert.FromHexString(nonceHex));

		crypto.Xor(source, actual);

		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}
}
