using CryptoBase;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.Macs.Poly1305;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace UnitTest
{
	[TestClass]
	public class Poly1305Test
	{
		private static void Test(IMac mac, string plainHex, string cipherHex)
		{
			Span<byte> plain = plainHex.FromHex();
			Span<byte> cipher = cipherHex.FromHex();
			Span<byte> o = stackalloc byte[16];

			Assert.AreEqual(@"Poly1305", mac.Name);

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
		public void Test(string keyHex, string plainHex, string cipherHex)
		{
			var key = keyHex.FromHex();
			Test(new Poly1305SF(key), plainHex, cipherHex);
			Test(new Poly1305X86(key), plainHex, cipherHex);
			Test(Poly1305Utils.Create(key), plainHex, cipherHex);
		}
	}
}
