using CryptoBase;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace UnitTest
{
	[TestClass]
	public class Salsa20Test
	{
		private static void Test(SnuffleCryptoBase crypto, string hex0, string hex1, string hex2, string hex3)
		{
			Assert.AreEqual(@"Salsa20", crypto.Name);
			Assert.AreEqual(8, crypto.IvSize);

			Span<byte> h0 = hex0.FromHex();
			Span<byte> h1 = hex1.FromHex();
			Span<byte> h2 = hex2.FromHex();
			Span<byte> h3 = hex3.FromHex();

			Span<byte> i = stackalloc byte[512];
			Span<byte> o = stackalloc byte[512];

			crypto.Update(i.Slice(0, 63), o); // 0 - 62
			Assert.IsTrue(o.Slice(0, 63).SequenceEqual(h0.Slice(0, 63)));
			crypto.Update(i.Slice(0, 63), o); // 63 - 125
			Assert.AreEqual(h0[63], o[0]);

			// 126 - 65456
			for (var j = 0; j < 1037; j++)
			{
				crypto.Update(i.Slice(0, 63), o);
			}

			crypto.Update(i.Slice(0, 63), o); // 65457 - 65519
			Assert.IsTrue(o.Slice(15, 63 - 15).SequenceEqual(h1.Slice(0, 48)));
			crypto.Update(i.Slice(0, 63), o); // 65520 - 65582
			Assert.IsTrue(o.Slice(0, 16).SequenceEqual(h1.Slice(48)));
			Assert.IsTrue(o.Slice(16, 47).SequenceEqual(h2.Slice(0, 47)));

			crypto.Update(i.Slice(0, 64), o); // 65583 - 65646
			Assert.IsTrue(o.Slice(0, 17).SequenceEqual(h2.Slice(47)));

			// 65647 - 130990
			for (var j = 0; j < 1021; j++)
			{
				crypto.Update(i.Slice(0, 64), o);
			}
			crypto.Update(i.Slice(0, 64), o); // 130991 - 131054
			Assert.IsTrue(o.Slice(17, 64 - 17).SequenceEqual(h3.Slice(0, 47)));
			crypto.Update(i.Slice(0, 64), o); // 131055 - 131118
			Assert.IsTrue(o.Slice(0, 17).SequenceEqual(h3.Slice(47)));

			crypto.Reset();

			crypto.Update(i.Slice(0, 128), o); // 0 - 127
			Assert.IsTrue(o.Slice(0, 64).SequenceEqual(h0));
			crypto.Update(i.Slice(0, 64), o); // 128 - 191

			// 192 - 65471
			for (var j = 0; j < 510; j++)
			{
				crypto.Update(i.Slice(0, 128), o);
			}
			crypto.Update(i.Slice(0, 128), o); // 65472 - 65599
			Assert.IsTrue(o.Slice(0, 64).SequenceEqual(h1));
			Assert.IsTrue(o.Slice(64, 64).SequenceEqual(h2));

			// 65600 - 130879
			for (var j = 0; j < 255; j++)
			{
				crypto.Update(i.Slice(0, 256), o);
			}
			crypto.Update(i.Slice(0, 256), o); // 130880 - 131135
			Assert.IsTrue(o.Slice(128, 64).SequenceEqual(h3));

			crypto.Reset();
			crypto.Update(i.Slice(0, 512), o); // 0 - 511
			Assert.IsTrue(o.Slice(0, 64).SequenceEqual(h0));

			// 512 - 65535
			for (var j = 0; j < 127; j++)
			{
				crypto.Update(i.Slice(0, 512), o);
			}
			Assert.IsTrue(o.Slice(448, 64).SequenceEqual(h1));
			crypto.Update(i.Slice(0, 512), o); // 65536 - 66047
			Assert.IsTrue(o.Slice(0, 64).SequenceEqual(h2));

			// 66048 - 131071
			for (var j = 0; j < 127; j++)
			{
				crypto.Update(i.Slice(0, 512), o);
			}
			Assert.IsTrue(o.Slice(448, 64).SequenceEqual(h3));
			crypto.Dispose();
		}

		/// <summary>
		/// https://github.com/das-labor/legacy/blob/master/microcontroller-2/crypto-lib/testvectors/salsa20-full-verified.test-vectors#L2068
		/// https://github.com/das-labor/legacy/blob/master/microcontroller-2/crypto-lib/testvectors/salsa20-full-verified.test-vectors#L4669
		/// </summary>
		[TestMethod]
		[DataRow(@"0053A6F94C9FF24598EB3E91E4378ADD", @"0D74DB42A91077DE",
				@"05E1E7BEB697D999656BF37C1B978806735D0B903A6007BD329927EFBE1B0E2A8137C1AE291493AA83A821755BEE0B06CD14855A67E46703EBF8F3114B584CBA",
				@"1A70A37B1C9CA11CD3BF988D3EE4612D15F1A08D683FCCC6558ECF2089388B8E555E7619BF82EE71348F4F8D0D2AE464339D66BFC3A003BF229C0FC0AB6AE1C6",
				@"4ED220425F7DDB0C843232FB03A7B1C7616A50076FB056D3580DB13D2C295973D289CC335C8BC75DD87F121E85BB998166C2EF415F3F7A297E9E1BEE767F84E2",
				@"E121F8377E5146BFAE5AEC9F422F474FD3E9C685D32744A76D8B307A682FCA1B6BF790B5B51073E114732D3786B985FD4F45162488FEEB04C8F26E27E0F6B5CD")]
		[DataRow(@"0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D", @"0D74DB42A91077DE",
				@"F5FAD53F79F9DF58C4AEA0D0ED9A9601F278112CA7180D565B420A48019670EAF24CE493A86263F677B46ACE1924773D2BB25571E1AA8593758FC382B1280B71",
				@"B70C50139C63332EF6E77AC54338A4079B82BEC9F9A403DFEA821B83F7860791650EF1B2489D0590B1DE772EEDA4E3BCD60FA7CE9CD623D9D2FD5758B8653E70",
				@"81582C65D7562B80AEC2F1A673A9D01C9F892A23D4919F6AB47B9154E08E699B4117D7C666477B60F8391481682F5D95D96623DBC489D88DAA6956B9F0646B6E",
				@"A13FFA1208F8BF50900886FAAB40FD10E8CAA306E63DF39536A1564FB760B242A9D6A4628CDC878762834E27A541DA2A5E3B3445989C76F611E0FEC6D91ACACC")]
		public void Test(string keyHex, string ivHex, string hex0, string hex1, string hex2, string hex3)
		{
			var key = keyHex.FromHex();
			var iv = ivHex.FromHex();
			Test(new BcSalsa20Crypto(key, iv), hex0, hex1, hex2, hex3);
			Test(new Salsa20CryptoSF(key, iv), hex0, hex1, hex2, hex3);
			Test(new Salsa20CryptoX86(key, iv), hex0, hex1, hex2, hex3);
			Test(StreamCryptoCreate.Salsa20(key, iv), hex0, hex1, hex2, hex3);
		}

	}
}
