using CryptoBase.Ciphers.Streams;

namespace CryptoBase.Tests.Ciphers.Streams;

public class ChaCha20OriginalTest
{
	[Test]
	[Arguments
	(
		"0A5DB00356A9FC4FA2F5489BEE4194E73A8DE03386D92C7FD22578CB1E71C417",
		"1F86ED54BB2289F0",
		"A2590E1FB8142241D7CDBAD75DA35762A2C71E2D5CD650FA5E090C91D9E3A2EF5550E94A5939ED559F0DBF5E802DA83AC340D5148C1C147C2432ED9CF61D9C6B"
	)]
	[Arguments
	(
		"3A8DE03386D92C7FD22578CB1E71C417",
		"1F86ED54BB2289F0",
		"6C0962D7BD66E54FCA23C27E0F2EE84475817264DFE9EB845FA9BB1FD6FD8EE4BEFE109A878DD118506BCA4B7A32BA7811E326AFB953DC20FB3962FF6270C95E"
	)]
	public async Task VerifiedFirstBlockForBothKeySizes(string keyHex, string nonceHex, string expectedHex)
	{
		byte[] key = Convert.FromHexString(keyHex);
		byte[] nonce = Convert.FromHexString(nonceHex);
		byte[] expected = Convert.FromHexString(expectedHex);
		byte[] source = new byte[64];
		byte[] actual = new byte[source.Length];
		using ChaCha20OriginalCipher crypto = new(key, nonce);

		crypto.Xor(source, actual);

		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}
}
