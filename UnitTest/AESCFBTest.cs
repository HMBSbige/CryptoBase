using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;
using CryptoBase.DataFormatExtensions;
using CryptoBase.SymmetricCryptos.StreamCryptos;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace UnitTest
{
	[TestClass]
	public class AESCFBTest
	{
		private static void Test(IStreamCrypto crypto, string hex, string hex2)
		{
			Assert.AreEqual(@"AES-CFB", crypto.Name);

			Span<byte> h1 = hex.FromHex();
			Span<byte> h2 = hex2.FromHex();

			Span<byte> o = stackalloc byte[h1.Length];

			crypto.Update(h1, o);
			Assert.IsTrue(o.SequenceEqual(h2));

			crypto.Reset();

			crypto.Update(h1[..73], o);
			crypto.Update(h1[73..], o[73..]);
			Assert.IsTrue(o.SequenceEqual(h2));

			crypto.Dispose();
		}

		/// <summary>
		/// https://gchq.github.io/CyberChef/#recipe=AES_Encrypt(%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D,'CFB','Hex','Hex','')AES_Decrypt(%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D,'CFB','Hex','Hex',%7B'option':'Hex','string':''%7D,'')
		/// </summary>
		[TestMethod]
		[DataRow(@"A0B0C0D0E0F1011121314151617181AA", @"fe3577795961e1fbbbb82528c74d2e99",
			@"4dfa5e481da23ea09a31022050859936da52fcee218005164f267cb65f5cfd7f2b4f97e0ff16924a52df269515110a07f9e460bc65ef95da58f740b7d1dbb0aada9c1581f429e0a00f7d67e23b730676783b262e8eb43a25f55fb90b3e753aef8c6713ec66c51881111593ccb3e8cb8f8de124080501eeeb389c4bcb6977cf950558abfe51a4f74a9df04396e93c8fe23588db2e81d4277acd2073c6196cbf120a5db00356a9fc4fa2f5489bee4194e73a8de03386d92c7fd22578cb1e71c4170f62b5085bae0154a7fa4da0f34699ec3f92e5388bde3184d72a7dd02376c91c0053a6f94c9ff24598eb3e91e4378add3083d6297ccf2275c81b6ec11467ba",
			@"9f81c160fce82ba391927f7882c162d7d0b3e5fe776947d1af047de8c349a95abafa30ccc0563b28d669904e5e9bd76a3543bcadf47eb21c38d064daadd7b5c783bdc54b45a32d86febd7e6a3c694fd08ddcdeeb7a7bf0b438f1b645ab86d2a733c1c0e47a20a9d20caccadb7924ffc2fa9887a635b85f045484f13ca48723c07178162af73decf0f46f120b20173bbb39ea7a0178f42f3c9ddb90103bac8b3d670342f7ca3c62912b83f4853e6204c412e1bf1418a7cd0c044a104c209ba0e08726950ae67151c6172ed892899f5e477e3aa4eabb244a7b290411ac9f0c559f1494eb76fb35d497acef1d125299d79f095cd0de001b8192594e8fb1912b47")]
		[DataRow(@"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", @"00112233445566778899aabbccddeeff",
				@"2b13159cf228129b127df8799ab1b21882b00020dbfe3577795961e1fbbbb82528c74d2e9fa031d8a1f7e42c64a3f47f0e71ca172ca4ccf9af0ac9484550714afa9e04a0ba5a747a2ff4d14eebe0ad96b17684379f3a13588e2105b7f7b6b21d06b96e69ce2b2de07e64b76566cfc91e1859691393c77e1417b1a8c09b9b4675070bd39043c1f3ba47494fde4a3fae3c06cd3d9ec7ca5be4a14b0938c4848052d4ee4a64c25101c0f75dc55034dcfc1529f129fbb2f92b01aed7f279771ac9e75273f023030251fe8949ec35455d1e09f9c888ed5c2999c4b2ffdcafd714ba146051ef94faa056fc830506ee4734864897bc5b2d4b2fb32a74feb96739ea11",
				@"a5b1a256a34f5724f881b1e9d1f8d291ddc6719795ba274bb676f0d44809d6494fd6d92acbe770f53250b244501f5d8f9fd0b189dd142d1cbb2718b5601204f66e85bb32c54cbd4199d9895d7500ffaa7841c2fa89a9095e581e64a817150c8ad394a4a979f35684e8c8c4965c6043a2527e35a9d22adce74d948a825105872dc8c3f6b593e02d487ecc6708cfb1ed7ccc8c7b5c8dfc19aa9d4fb3379e13c332e6f403f464db0fb2f53ff9232475de4072104e2d7de576a1f84356b7a2c3a6b851b14a11f63ccc32f717207a238b0d8db3c02280793d3f8ca3236c717e23962d5d17f682240d4c116f3051da172142b26508a7df31a1bce85e696d06817093")]
		[DataRow(@"08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", @"00112233445566778899aabbccddeeff",
				@"a5b1a256a34f5724f881b1e9d1f8d29174cf8ed2970fb9bd0054ccb3b5e6015e087c4b3dbf90edade1815d338b6cf8f1bf133b07eecfc4d1bb69a1a04e0221332bc390d36eac23997ed11cbab1981b69466c22ab23f94bc96e16419f63ba03cff717ce0615e162dac024fda8d042155605e005753abbb15c0d002c75d66f9f5369a51336a1d8f6d65b65f803c3f4c4e3afb3794aa261678b7e5bc5009daa1d4aeab301b801c9ab4e0edeb359f4ea4775995638c5fad6a9b3ef72ef94ea04879d728fd52b15650b2b6210c9d2ad880496220b8a963e9325593ec9eb7eaecab1e5805aa0a36a837f7fbac31ff504ec539a48cbc3ab3a361c12618b34237d64f2",
				@"2291802d076e5ab69f2514c51b45db29e9603468b9bbf25d962785a95a051dde87d312a68ceef02717237b07ff05e6e403cfe5225c7a5053ee8c33f723e5e16996517a9ae17f8825369266237696a60ae8154955ae146168095d4edf9c457730379430bbc924eeefb2a982481eab60661b76493b0efddc3357d0f4f0363bc349de6c1a29522b00344a071b73da43c42febe5c72ec8ccfb63d1a34e1502196c60e206ee896a1cdda0d6d78307b86ac616a941f3f55cb0a47294a9e36baacebbd882b77a2666dcf1ef551acebb05b1c970d438b315e72037fe13b4bc2913fcc9fed13ea331138608689afc9b485096497abb50227780a6f0b9c678029e9443a8")]
		public void Test(string keyHex, string ivHex, string hex, string hex2)
		{
			var key = keyHex.FromHex();
			var iv = ivHex.FromHex();
			Test(new BcAESCFBStreamCrypto(true, key, iv), hex, hex2);
			Test(new BcAESCFBStreamCrypto(false, key, iv), hex2, hex);
			Test(StreamCryptoCreate.AesCfb(true, key, iv), hex, hex2);
			Test(StreamCryptoCreate.AesCfb(false, key, iv), hex2, hex);
		}
	}
}
