using CryptoBase;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.Macs.GHash;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace UnitTest
{
	[TestClass]
	public class GHashTest
	{
		private static void Test(IMac mac, string plainHex, string cipherHex)
		{
			Span<byte> plain = plainHex.FromHex();
			Span<byte> cipher = cipherHex.FromHex();
			Span<byte> o = stackalloc byte[16];

			Assert.AreEqual(@"GHash", mac.Name);

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
		/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
		/// https://www.intel.cn/content/dam/www/public/us/en/documents/white-papers/carry-less-multiplication-instruction-in-gcm-mode-paper.pdf
		/// </summary>
		[TestMethod]
		[DataRow(@"dfa6bf4ded81db03ffcaff95f830f061", @"952b2a56a5604ac0b32b6656a05b40b6", @"da53eb0ad2c55bb64fc4802cc3feda60")]
		[DataRow(@"66e94bd4ef8a2c3b884cfa59ca342b2e", @"0388dace60b6a392f328c2b971b2fe78", @"5e2ec746917062882c85b0685353deb7")]
		[DataRow(@"66e94bd4ef8a2c3b884cfa59ca342b2e", @"0388dace60b6a392f328c2b971b2fe7800000000000000000000000000000080", @"f38cbb1ad69223dcc3457ae5b6b0f885")]
		[DataRow(@"66e94bd4ef8a2c3b884cfa59ca342b2e", @"0388dace60b6a392f328c2b971b2fe7ad2c55bb64f", @"c1d3b69b62c9a392687aaf55d95a1df6")]
		public void Test(string keyHex, string plainHex, string cipherHex)
		{
			var key = keyHex.FromHex();
			Test(new GHashSF(key), plainHex, cipherHex);
			Test(new GHashX86(key), plainHex, cipherHex);
			Test(GHashUtils.Create(key), plainHex, cipherHex);
		}
	}
}
