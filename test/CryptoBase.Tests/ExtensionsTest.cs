namespace CryptoBase.Tests;

public class ExtensionsTest
{
	[Theory]
	[InlineData(@"", 5381)]
	[InlineData(@"abc", -1549454715)]
	[InlineData(@"abcde", 511372036)]
	[InlineData(@"abcdez", -308130818)]
	[InlineData(@"d60e1c2860a249ddb96ddfebbb618a53daa635b1c504409c935ffab4", -237686059)]
	[InlineData(@"d60e1c2860a249ddb96ddfebbb618a53daa635b1c504409c935ffab41a0d", 678771057)]
	[InlineData(@"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", -1951733499)]
	[InlineData(@"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", -1610044155)]
	public void GetDeterministicHashCodeTest(string str, int hash)
	{
		Assert.Equal(hash, str.GetDeterministicHashCode<char>());
	}
}
