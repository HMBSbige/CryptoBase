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
	[DataRow(@"957662F0F3757BBC2224101E7EEB5FAF", @"DFC696A260924A776E00967D", @"0284CBF574F66458A3CD31BA17D49D31C5925FC8D7E68B64726EDBAF04D6B8CD",
		@"F58A930BE914BA9F361F165B9483C6A7",
		@"F55A60B7207C0AC615608D9E11C10B3B7724A443992B09A28BC3DE86612B97883154FC2D16F1532625C0DC95109DBA3ECB9C83D4E78AFE7F61B3FE0A748C0558C67A52D4F25619C8EFF0DAD073B5C146D35CEF09C6F8BB9B9AF74875ABAFDB6EB8C79BB5CB554828A9C84DACAD4E519A0A2D6E69B078D3A9423C62DCA8BC6BF8AFA63394D255451620248977527D026A04C6BDBE629F0B87371F4BB70D4A9371292A6EA1518B44CF4BF36075A5A4A1469E1EA805293F42B042C5F3768D99FDF7F85B1BDC3831CD0DD28D87A53D60E63164E2B9E67523F0B21E08BCFA699D04FEC0D93AB5E3A228CD86D2CA025EC6B1356F117D8A5CC9FCA87B991C026F7265A1613353767859F1EAB82A98ECEC9445FA23DEBF7AAF7B0F1C25C58E9822BBFE53F434ABB4174F45762628D21B2E3C3E4757B78C8491E97AE2BAF7A1E885AFBD7F900758251110A8E98314B6285540760E904F8D09D45CF5F8827B12B423CB8D5351C2BDD5EE8800268C429D867E80C8C0272F2A3B7D43DC5B4C574456DFEB776076B80FB2ED848B9407E50A18011F2524CC1A6AF87247CE4E11B5D93D578C2DC97332B7687A42D904D6CB7C7ECF3B0271C817F3F01452638BD05CD6E2804FF0829EAA1E89BC88E5A1BB8B066B8188C1D97503B77F36DD57BCB4FE16D0572FBCE3F5F64379E43B105A84D727201EA2A551F35B6B0E7BC3FE40E79680B9088438",
		@"66E0F0AA3F5C329D0CBCF661054103BD1ED72432B41ACF62C258A65C8D2EF30EB0205E87271B5E3DA4F71582CDF3BD4F090EEF725BD4F8BB2A3DD441883A6188B381FAE71B6EDC99A6C0CEB1B5DA18BFFF048DCBFB0E19F4DC88B14969287F7A86806A794923DC3A4720002BF8E7C16265C18A21C636AAED2D952B95D51938820D1FBE319B64A4700D0BC6A5AE764302484A2CB598C85BBB5909D0797F17762AC7834B0918A986399C625FECF3A7B66372ECD54329FBCC8C900F52B76B1EF32719063D50037D5384B67BBFA5869DFCFDE535D4FA574C5E2C4D063FBDF76F96356AB7C357D4E8657A7BFE80E7F57681177575B5F070DD1D5E9B1792FDF56108EB3862459D4B53E203A5D0C3077346473FB78F70C4A8ACAD467B5A90960E38169A849153C4ED67D86DBE93EC5E66895C4FAED2E59D8830A1125A380572B7B420B45BD05E8B914933197B8DE9E1015EF55A7B5283AD6B02C685977E0D6C234FADD297183E8E80109A64C1146327BC39736C3385672826BB436E144FFF02A93C27ED177CFF304536B6BE391354A10DFC0403E26A04C5222AEC7CBB17BA3810ADDE3EE4F0117A93DBFD66BDE6480A4442CC889DD2E7CEE61772D671196EB1B09D12213FE8B6C85CF0BC0125A970CAA9C5B8719F14BE541BD1931222885C5EB2F09A7E6FAC546EF4CC62913972D464E0990E3900D5396691214994E9BD56177A6894")]
	public void Test(string keyHex, string nonceHex, string associatedDataHex, string tagHex, string plainHex, string cipherHex)
	{
		var key = keyHex.FromHex();
		Test(AEADCryptoCreate.Sm4Gcm(key), nonceHex, associatedDataHex, tagHex, plainHex, cipherHex);
	}
}
