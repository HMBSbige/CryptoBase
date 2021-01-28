using CryptoBase;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace UnitTest
{
	[TestClass]
	public class ChaCha20OriginalTest
	{
		private static void Test(SnuffleCryptoBase crypto, string hex)
		{
			Assert.AreEqual(@"ChaCha20Original", crypto.Name);
			Assert.AreEqual(8, crypto.IvSize);

			Span<byte> h1 = hex.FromHex();
			Span<byte> i1 = stackalloc byte[255];
			Span<byte> o1 = stackalloc byte[255];

			crypto.Encrypt(i1, o1);
			Assert.IsTrue(o1.SequenceEqual(h1));

			crypto.Dispose();
		}

		[TestMethod]
		[DataRow(@"0A5DB00356A9FC4FA2F5489BEE4194E73A8DE03386D92C7FD22578CB1E71C417",
			@"1F86ED54BB2289F0",
			@"A2590E1FB8142241D7CDBAD75DA35762A2C71E2D5CD650FA5E090C91D9E3A2EF5550E94A5939ED559F0DBF5E802DA83AC340D5148C1C147C2432ED9CF61D9C6BF68C20446F8E1C144190C6DC270661C86375E7B5023C16E7144CBE5A945313E001BCDC5A99B2F87B8D8A036D2BE83EC219826ACF7BB259100BA9525F2D71E3CF666434768F72D05B57E257D6688B51E06507EF5541AE99ED9BB8C1A83A4BD7F4589691DA7A68D3B44EB945E779476B13061338FF18AA0B88BF4B557E2D7B2E36F7463B43D4FB053903ED42EEB192FD649E00200FAA15179DA494AD8198E7A4601CBF29FBE297191D026B293FE2D6F949C9D6688E283EF3C83CB896EF35DED0")]
		public void Test(string keyHex, string ivHex, string hex)
		{
			var key = keyHex.FromHex();
			var iv = ivHex.FromHex();
			Test(new BcChaCha20OriginalCrypto(key, iv), hex);
		}
	}
}
