using CryptoBase;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos.XSalsa20;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace UnitTest
{
	[TestClass]
	public class XSalsa20Test
	{
		private static void Test(SnuffleCryptoBase crypto, string i1, string o1, string i2, string o2)
		{
			Assert.AreEqual(@"XSalsa20", crypto.Name);
			Assert.AreEqual(24, crypto.IvSize);

			Span<byte> h1 = i1.FromHex();
			Span<byte> g1 = o1.FromHex();

			Span<byte> h2 = i2.FromHex();
			Span<byte> g2 = o2.FromHex();

			Span<byte> x1 = stackalloc byte[h1.Length];
			Span<byte> x2 = stackalloc byte[h2.Length];

			crypto.Update(h1, x1);
			Assert.IsTrue(x1.SequenceEqual(g1));

			crypto.Update(h2, x2);
			Assert.IsTrue(x2.SequenceEqual(g2));

			crypto.Reset();

			crypto.Update(g1, x1);
			Assert.IsTrue(x1.SequenceEqual(h1));

			crypto.Update(g2, x2);
			Assert.IsTrue(x2.SequenceEqual(h2));

			crypto.Dispose();
		}

		[TestMethod]
		[DataRow(
				@"a6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff88030",
				@"9e645a74e9e0a60d8243acd9177ab51a1beb8d5a2f5d700c",
				@"093c5e55855796", @"b2af688e7d8fc4",
				@"25337bd3ab619d615760d8", @"b508c05cc39dd583d67143")]
		[DataRow(
				@"9e1da239d155f52ad37f75c7368a536668b051952923ad44f57e75ab588e475a",
				@"af06f17859dffa799891c4288f6635b5c5a45eee9017fd72",
				@"feac9d54fc8c115ae247d9a7e919dd76cfcbc72d32cae4944860817cbdfb8c04e6", @"2c261a2f4e61a62e1b27689916bf03453fcbc97bb2af6f329391ef063b5a219bf9",
				@"b1df76a16517cd33ccf1acda9206389e9e", @"84d07d70f602d85f6db61474e9d9f5a2de")]
		[DataRow(
				@"d5c7f6797b7e7e9c1d7fd2610b2abf2bc5a7885fb3ff78092fb3abe8986d35e2",
				@"744e17312b27969d826444640e9c4a378ae334f185369c95",
				@"7758298c62", @"27b8cfe814",
				@"8eb3a4b6963c5445ef66971222be5d1a4ad839715d1188071739b77cc6e05d5410f963a641", @"16a76301fd1eec6a4d99675069b2da2776c360db1bdfea7c0aa613913e10f7a60fec04d11e")]
		[DataRow(
				@"737d7811ce96472efed12258b78122f11deaec8759ccbd71eac6bbefa627785c",
				@"6fb2ee3dda6dbd12f1274f126701ec75c35c86607adb3edd",
				@"501325fb2645264864df11faa17bbd58", @"6724c372d2e9074da5e27a6c54b2d703",
				@"312b77cad3d94ac8fb8542f0eb653ad7", @"dc1d4c9b1f8d90f00c122e692ace7700")]
		[DataRow(
				@"760158da09f89bbab2c99e6997f9523a95fcef10239bcca2573b7105f6898d34",
				@"43636b2cc346fc8b7c85a19bf507bdc3dafe953b88c69dba",
				@"d30a6d42dff49f0ed039a306bae9dec8d9e88366cc19e8c3642fd58fa079", @"c815b6b79b64f9369aec8dce8c753df8a50f2bc97c70ce2f014db33a65ac",
				@"4ebf8029d949730339b0823a51f0f49f0d2c71f1051c1e0e2c86941f1727", @"5816bac9e30ac08bdded308c65cb87e28e2e71b677dc25c5a6499c155355")]
		[DataRow(
				@"27ba7e81e7edd4e71be53c07ce8e633138f287e155c7fa9e84c4ad804b7fa1b9",
				@"ea05f4ebcd2fb6b000da0612861ba54ff5c176fb601391aa",
				@"e09ff5d2cb050d69b2d42494bde5825238c756d6991d99d7a20d1ef0b83c371c89872690b2", @"a23e7ef93c5d0667c96d9e404dcbe6be62026fa98f7a3ff9ba5d458643a16a1cef7272dc60",
				@"fc11d5369f4fc4971b6d3d6c078aef9b0f05c0e61ab89c025168054defeb03fef633858700", @"97a9b52f35983557c77a11b314b4f7d5dc2cca15ee47616f861873cbfed1d32372171a61e3")]
		public void Test(string keyHex, string ivHex, string i1, string o1, string i2, string o2)
		{
			var key = keyHex.FromHex();
			var iv = ivHex.FromHex();
			Test(new BcXSalsa20Crypto(key, iv), i1, o1, i2, o2);
			Test(new XSalsa20CryptoX86(key, iv), i1, o1, i2, o2);
			Test(new XSalsa20CryptoSF(key, iv), i1, o1, i2, o2);
		}
	}
}
