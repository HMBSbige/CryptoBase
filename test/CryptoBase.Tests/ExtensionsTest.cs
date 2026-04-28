namespace CryptoBase.Tests;

public class ExtensionsTest
{
	[Test]
	[Arguments(@"", 5381)]
	[Arguments(@"abc", -1549454715)]
	[Arguments(@"abcde", 511372036)]
	[Arguments(@"abcdez", -308130818)]
	[Arguments(@"d60e1c2860a249ddb96ddfebbb618a53daa635b1c504409c935ffab4", -237686059)]
	[Arguments(@"d60e1c2860a249ddb96ddfebbb618a53daa635b1c504409c935ffab41a0d", 678771057)]
	[Arguments(@"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", -1951733499)]
	[Arguments(@"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", -1610044155)]
	public async Task GetDeterministicHashCodeTest(string str, int hash)
	{
		await Assert.That(str.GetDeterministicHashCode<char>()).IsEqualTo(hash);
	}
}
