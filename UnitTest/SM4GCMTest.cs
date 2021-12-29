using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.DataFormatExtensions;
using CryptoBase.SymmetricCryptos.AEADCryptos;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTest;

[TestClass]
public class SM4GCMTest
{
	private static void Test(IAEADCrypto crypto, string nonceHex, string associatedDataHex, string tagHex, string plainHex, string cipherHex)
	{
		Assert.AreEqual(@"SM4-GCM", crypto.Name);

		crypto.AEADTest(nonceHex, associatedDataHex, tagHex, plainHex, cipherHex);
	}

	/// <summary>
	///https://tools.ietf.org/html/rfc8998#appendix-A.1
	/// </summary>
	[TestMethod]
	[DataRow(@"0123456789ABCDEFFEDCBA9876543210", @"00001234567800000000ABCD", @"FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2",
		@"83DE3541E4C2B58177E065A9BF7B62EC",
		@"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA",
		@"17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D")]
	public void Test(string keyHex, string nonceHex, string associatedDataHex, string tagHex, string plainHex, string cipherHex)
	{
		var key = keyHex.FromHex();
		Test(AEADCryptoCreate.Sm4Gcm(key), nonceHex, associatedDataHex, tagHex, plainHex, cipherHex);
	}
}
