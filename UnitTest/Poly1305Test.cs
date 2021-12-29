using CryptoBase.Abstractions;
using CryptoBase.DataFormatExtensions;
using CryptoBase.Macs.Poly1305;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace UnitTest;

[TestClass]
public class Poly1305Test
{
	private static void Test(IMac mac, string plainHex, string cipherHex)
	{
		Span<byte> plain = plainHex.FromHex();
		Span<byte> cipher = cipherHex.FromHex();
		Span<byte> o = stackalloc byte[mac.Length];

		Assert.AreEqual(@"Poly1305", mac.Name);
		Assert.AreEqual(16, mac.Length);

		mac.Update(plain);
		mac.GetMac(o);

		Assert.IsTrue(o.SequenceEqual(cipher));

		mac.Update(plain);
		mac.GetMac(o);

		Assert.IsTrue(o.SequenceEqual(cipher));

		mac.Update(plain);
		mac.Reset();

		mac.Update(plain);
		mac.GetMac(o);

		Assert.IsTrue(o.SequenceEqual(cipher));

		mac.Dispose();
	}

	/// <summary>
	/// https://tools.ietf.org/html/rfc8439
	/// </summary>
	[TestMethod]
	[DataRow(@"85D6BE7857556D337F4452FE42D506A80103808AFB0DB2FD4ABFF6AF4149F51B", @"43727970746F6772617068696320466F72756D2052657365617263682047726F7570", @"c88886f51af32a75f0fdf57c4a7defdd")]
	[DataRow(@"746869732069732033322d62797465206b657920666f7220506f6c7931333035", @"48656c6c6f20776f726c6421", @"cf76f9033b46a114c8ba0577105cc8ed")]
	[DataRow(@"746869732069732033322d62797465206b657920666f7220506f6c7931333035", @"85D6BE7857556D337F4452FE42D506A80103808AFB0DB2FD4ABFF6AF4149F51B746869732069732033322d62797465206b657920666f7220506f6c793133303543727970746F6772617068696320466F72756D2052657365617263682047726F75708A438BDEE65C422A8366A2F85E5E93972FF925F667EB483EB01B1CD6C9", @"b0c63d86c91980a61c0824fb5cf618cc")]
	[DataRow(@"746869732069732033322d62797465206b657920666f7220506f6c7931333035", @"ec74691700388dace60b6a392f328c2b971b2f952b2a56a5604ac0b66e94bd4ef8a2c3b884cfa59ca342b2e3da53ec1d3b69b62c9a392687aaf55d95a1df6b0ad2c55bb64fc4802cc3feda602b6656a05b40b6e7ad2c55bb64f62882c85b0685353deb7f38cbb1ad69223dcc3457ae5b6b0dfa6bf4ded81d", @"c783ec8f3716299f4e74a76f4e03296b")]
	public void Test(string keyHex, string plainHex, string cipherHex)
	{
		var key = keyHex.FromHex();
		Test(new Poly1305SF(key), plainHex, cipherHex);
		Test(new Poly1305X86(key), plainHex, cipherHex);
		Test(Poly1305Utils.Create(key), plainHex, cipherHex);
	}
}
