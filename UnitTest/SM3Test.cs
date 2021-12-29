using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.DataFormatExtensions;
using CryptoBase.Digests.SM3;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace UnitTest;

[TestClass]
public class SM3Test
{
	private static void SM3DigestTest(IHash sm3, string str, string sm3Str)
	{
		Assert.AreEqual(@"SM3", sm3.Name);
		Assert.AreEqual(32, sm3.Length);
		Assert.AreEqual(64, sm3.BlockSize);

		Span<byte> origin = Encoding.UTF8.GetBytes(str);
		Span<byte> hash = stackalloc byte[sm3.Length];

		sm3.UpdateFinal(origin, hash);
		sm3.UpdateFinal(origin, hash);

		Assert.AreEqual(sm3Str, hash.ToHex());

		sm3.Update(origin);
		sm3.GetHash(hash);

		Assert.AreEqual(sm3Str, hash.ToHex());

		sm3.Update(origin);
		sm3.Reset();

		sm3.Update(origin[..(origin.Length / 2)]);
		sm3.Update(origin[(origin.Length / 2)..]);
		sm3.GetHash(hash);

		Assert.AreEqual(sm3Str, hash.ToHex());

		sm3.Update(origin[..(origin.Length / 2)]);
		sm3.UpdateFinal(origin[(origin.Length / 2)..], hash);

		Assert.AreEqual(sm3Str, hash.ToHex());

		sm3.Dispose();
	}

	/// <summary>
	/// https://gchq.github.io/CyberChef/#recipe=SM3(256,64)
	/// </summary>
	[TestMethod]
	[DataRow(@"", @"1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b")]
	[DataRow(@"abc", @"66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")]
	[DataRow(@"abcde", @"afe4ccac5ab7d52bcae36373676215368baf52d3905e1fecbe369cc120e97628")]
	[DataRow(@"abcdez", @"897671415764167c85037e3bba4cc0f8fa019accd94730f0188b5c74bc502912")]
	[DataRow(@"d60e1c2860a249ddb96ddfebbb618a53daa635b1c504409c935ffab4", @"ab00404a6acb46f48ee28b42354ce984adb2e19b11a4675a5a043f62506fe117")]
	[DataRow(@"d60e1c2860a249ddb96ddfebbb618a53daa635b1c504409c935ffab41a0d", @"2b9bdd2ffbe3f293744af51b181cdb36a6bf0d5065306a56a7b8c5a5cb2e03d1")]
	[DataRow(@"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", @"debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732")]
	[DataRow(@"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", @"f07b76f62b616de94e6ef9733db1953b8e3fa55014c3f4667abf2ea60aa44250")]
	public void SM3DigestTest(string str, string sm3Str)
	{
		SM3DigestTest(new BcSM3Digest(), str, sm3Str);
		SM3DigestTest(new SM3Digest(), str, sm3Str);
	}

#if LongTimeTest
		[TestMethod]
#endif
	[DataRow(@"euasxpm", @"de27a8b04cf2bde6c963fc0d8df4fdceee26f03a9f0d1ff80e5773817444f172")]
	public void LargeMessageTest(string str, string result)
	{
		TestUtils.LargeMessageTest(new BcSM3Digest(), str, result);
		TestUtils.LargeMessageTest(new SM3Digest(), str, result);
	}
}
