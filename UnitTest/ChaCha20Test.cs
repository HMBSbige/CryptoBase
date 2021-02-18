using CryptoBase;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace UnitTest
{
	[TestClass]
	public class ChaCha20Test
	{
		private static void Test(SnuffleCryptoBase crypto, string hex, string hex2)
		{
			Assert.AreEqual(@"ChaCha20", crypto.Name);
			Assert.AreEqual(12, crypto.IvSize);

			Span<byte> h1 = hex.FromHex();
			Span<byte> h2 = hex2.FromHex();
			Span<byte> i1 = stackalloc byte[255];
			Span<byte> o1 = stackalloc byte[i1.Length];

			h1.CopyTo(i1.Slice(64));

			crypto.Update(i1, o1);
			Assert.IsTrue(o1.Slice(64, 114).SequenceEqual(h2));

			crypto.Reset();

			h1.CopyTo(i1.Slice(64));

			crypto.Update(i1, o1);
			Assert.IsTrue(o1.Slice(64, 114).SequenceEqual(h2));

			crypto.Dispose();
		}

		/// <summary>
		/// https://tools.ietf.org/html/rfc8439#section-2.4.2
		/// </summary>
		[TestMethod]
		[DataRow(@"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			@"000000000000004A00000000",
			@"6E2E359A2568F98041BA0728DD0D6981E97E7AEC1D4360C20A27AFCCFD9FAE0BF91B65C5524733AB8F593DABCD62B3571639D624E65152AB8F530C359F0861D807CA0DBF500D6A6156A38E088A22B65E52BC514D16CCF806818CE91AB77937365AF90BBF74A35BE6B40B8EEDF2785E42874D",
			@"4C616469657320616E642047656E746C656D656E206F662074686520636C617373206F66202739393A204966204920636F756C64206F6666657220796F75206F6E6C79206F6E652074697020666F7220746865206675747572652C2073756E73637265656E20776F756C642062652069742E")]
		public void Test(string keyHex, string ivHex, string hex, string hex2)
		{
			var key = keyHex.FromHex();
			var iv = ivHex.FromHex();
			Test(new BcChaCha20Crypto(key, iv), hex, hex2);
			Test(new ChaCha20CryptoSF(key, iv), hex, hex2);
			Test(new ChaCha20CryptoX86(key, iv), hex, hex2);
		}
	}
}
