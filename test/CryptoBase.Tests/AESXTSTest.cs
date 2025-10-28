using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.DataFormatExtensions;
using CryptoBase.SymmetricCryptos.BlockCryptoModes.Xts;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
using System.Security.Cryptography;

namespace CryptoBase.Tests;

public class AESXTSTest
{
	public static readonly TheoryData<string, UInt128, string, string> Data = new()
	{
		{ "a3e40d5bd4b6bbedb2d18c700ad2db2210c81190646d673cbca53f133eab373c", 141, "20e0719405993f09a66ae5bb500e562c", "74623551210216ac926b9650b6d3fa52" },
		{ "a2ed35e8d082f5e13e78c1d42acf33cf70e82821a666b2a7606542e43a631226", 75, "2d81dcdec507845dcac4af1594aac844", "050dc32995cf6cd87224dfa2572709f4" },
		{ "69438582e0a61b5e7a023adf2f419630ed537ccf9a4b2e09010eaf7b66bcf818", 232, "05c2c05e812bc4295f3ef64c8bc468ee946176449edc481785e6c6d9fbdd6b8f", "27259ec330a66591e265525cd1eb5017ba195a390e4f66ddfb7c1a4b0fb5e49d" },
		{ "f5409a68908c710aacc31a223ef7911db3202772edd955663a75292d9384ca2c", 100, "ce1a975b08eec5a005708cd4113a701fb0377b14b59e70dc06fe6941121f16a2", "39d7b54434622b53a78529043bffa0f637e46a79c880cae70c67b1f2077e1932" },
		{ "fb46fb3cab7f67ad5207bc232c50dcbb24dbd1564590855d4cb777b3ba6431c3", 117, "46409f7426eb4e3d33480534b80fe6e09fed6583907eb83c84", "a19d9b3209d388740a581975091fe26deecbb0f117c22b0ae4" },
		{ "583d530d49942feafac523b980b816005759db2856ba62299783fc0f24da6066", 104, "a8378b828f615d5f8c5e394aaa9a3de3f49cee701d661f23b5", "d4ee9facfea79ae857fd43e25da5d950b1a1e6277e9fa50a3d" },
		{ "ef010ca1a3663e32534349bc0bae62232a1573348568fb9ef41768a7674f507a727f98755397d0e0aa32f830338cc7a926c773f09e57b357cd156afbca46e1a0", 187, "ed98e01770a853b49db9e6aaf88f0a41b9b56e91a5a2b11d40529254f5523e75", "ca20c55e8dc149687d2541de39c3df6300bb5a163c10ced3666b1357db8bd39d" },
		{ "c4e6b37e1075969d41a7601aa105dd41b18200a028da1f79f55c4d2db478c4e98d9ed491cfe52f31ecb7cbb4891eb779e057392b3b27c19cbe9b4875c8c31c22", 223, "87ede402d0561359799a41be042ced9a8e15639165ef1a4d2f6785c394d61e5f", "a51037198f3f9fe5d05bef52363acec40e86e3abb834180348d2e08627733e65" },
		{ "f6db5326ea996b16ca0d439b5a0106e3a34ed343db489faad06979009399b03b3cd9ef23332d46414216531d9885a5a30b1964523992f42748202b80a4190d45", 245, "bf6a09f93f94d6bdc8c5f5e158916c3371a540e46644f79414d84dda1339397ce90ebb768deeb88ecd2be175a396bb85", "b11a252c5776c439ea7baeaae7830418e574b2248cc8b524b7fd0cc8e1ecffa9812f45ae313e3e1f44127b27fb08a613" },
		{ "182614c12c49df2a50b8f9e985e9674253f141c17b6d440fcbbe4319d7034a87fe4db5c45e54086f62fde76999099fa71a3aae56c6a3220e226ccc2147f83a4f", 185, "e6f5621b062241c835e6fed103c089c782ceeab7035f4c6bb47bc35416599174b53608918c3ee5da1ab9736d8c8decc3", "9b2e2eef1b8c24a78f8ed47a0d30d8c8badbf70cf138292dfc2d3dc211aabc2e4ec0ef36c94e0505255e3acc5e13943a" }
	};

	public static readonly TheoryData<string, string, string, string> Data2 = new()
	{
		{ "a1b90cba3f06ac353b2c343876081762090923026e91771815f29dab01932f2f", "4faef7117cda59c66e4b92013e768ad5", "ebabce95b14d3c8d6fb350390790311c", "778ae8b43cb98d5a825081d5be471c63" },
		{ "8f59462c1327fd6411cb6b02c04bf0a129f145c276a38693c745de3118c90a2f", "f2b86793b29e730e4a627b6ee161706c", "f7049f8aa312aeb1ab99ad11a1d7a720", "e59fca86c3c906f3df67418636a28767" },
		{ "b7b93f516aef295eff3a29d837cf1f135347e8a21dae616ff5062b2e8d78ce5e", "873edea653b643bd8bcf51403197ed14", "236f8a5b58dd55f6194ed70c4ac1a17f1fe60ec9a6c454d087ccb77d6b638c47", "22e6a3c6379dcf7599b052b5a749c7f78ad8a11b9f1aa9430cf3aef445682e19" },
		{ "750372c3d82f63382867be6662acfa4a259be3fa9bc662a1154ffaaed8b448a5", "93a29254c47e4260669621307d4f5cd3", "d8e3a56559a436ce0d8b212c80a88b23af62b0e598f208e03c1f2e9fa563a54b", "495f7855535efd133464dc9a9abf8a0f28facbce21bd3c22178ec489b799e491" },
		{ "394c97881abd989d29c703e48a72b397a7acf51b59649eeea9b33274d8541df4", "4b15c684a152d485fe9937d39b168c29", "2f3b9dcfbae729583b1d1ffdd16bb6fe2757329435662a78f0", "f3473802e38a3ffef4d4fb8e6aa266ebde553a64528a06463e" },
		{ "8afb90c2ec924c4b0b0bd840fb1efc842c9385a14d1ca95bd4d12cbf9ab588ed", "b2f8c6374eb275c1744e85aa21f8ea6b", "d9d8f00683bcd489154882290f24624726e093390783d4959a", "f4bbaa8ebd480d2a2a371beab3d8b387c02282678c6000227b" },
		{ "1ea661c58d943a0e4801e42f4b0947149e7f9f8e3e68d0c7505210bd311a0e7cd6e13ffdf2418d8d1911c004cda58da3d619b7e2b9141e58318eea392cf41b08", "adf8d92627464ad2f0428e84a9f87564", "2eedea52cd8215e1acc647e810bbc3642e87287f8d2e57e36c0a24fbc12a202e", "cbaad0e2f6cea3f50b37f934d46a9b130b9d54f07e34f36af793e86f73c6d7db" },
		{ "e149be00177d76b7c1d85bcbb6b5054ee10b9f51cd73f59e0840628b9e7d854e2e1c0ab0537186a2a7c314bbc5eb23b6876a26bcdbf9e6b758d1cae053c2f278", "0ea18818fab95289b1caab4e61349501", "f5f101d8e3a7681b1ddb21bd2826b24e32990bca49b39291b5369a9bca277d75", "5bf2479393cc673306fbb15e72600598e33d4d8a470727ce098730fd80afa959" },
		{ "266c336b3b01489f3267f52835fd92f674374b88b4e1ebd2d36a5f457581d9d042c3eef7b0b7e5137b086496b4d9e6ac658d7196a23f23f036172fdb8faee527", "06b209a7a22f486ecbfadb0f3137ba42", "ca7d65ef8d3dfad345b61ccddca1ad81de830b9e86c7b426d76cb7db766852d981c6b21409399d78f42cc0b33a7bbb06", "c73256870cc2f4dd57acc74b5456dbd776912a128bc1f77d72cdebbf270044b7a43ceed29025e1e8be211fa3c3ed002d" },
		{ "7d12d5eaf687a3edf4ef0a284a6c7e9cfa075185e2608c2003b5f2719f81dec92d107279d6f1985b4b950e168b8af70b6e6e0b4419ddb50f425d673fa3714a38", "d63bba65b05d175a90de1003624e1d9f", "752e9b0b241e91fad431e0b900b5b697f875c0898d3d58b93b74723c032fd103bcc555a7b8be44a9d1e7726e7f31d2c7", "ad6f2c59c6130f0814bfebcb3f5e7833d6dbccb24c3311642806f965ff4435602d9d3e39851a495cfada67f8b3017ae7" }
	};

	private static void TestInternal(IBlockModeOneShot crypto, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> plain, ReadOnlySpan<byte> cipher)
	{
		Span<byte> buffer = stackalloc byte[plain.Length + 1];
		RandomNumberGenerator.Fill(buffer);

		crypto.Encrypt(iv, plain, buffer);
		Assert.True(buffer.Slice(0, plain.Length).SequenceEqual(cipher));

		crypto.Decrypt(iv, cipher, buffer);
		Assert.True(buffer.Slice(0, cipher.Length).SequenceEqual(plain));
	}

	[Theory]
	[MemberData(nameof(Data), MemberType = typeof(AESXTSTest))]
	public void TestDataUnitSeqNumber(string keyHex, UInt128 dataUnitSeqNumber, string plainHex, string cipherHex)
	{
		ReadOnlySpan<byte> key = keyHex.FromHex();
		Span<byte> iv = stackalloc byte[16];
		XtsMode.GetIv(iv, dataUnitSeqNumber);
		ReadOnlySpan<byte> plain = plainHex.FromHex();
		ReadOnlySpan<byte> cipher = cipherHex.FromHex();

		ReadOnlySpan<byte> key1 = key.Slice(0, key.Length >> 1);
		ReadOnlySpan<byte> key2 = key.Slice(key.Length >> 1);

		using IBlockCrypto dataCrypto = AESUtils.CreateECB(key1);
		using IBlockCrypto tweakCrypto = AESUtils.CreateECB(key2);

		TestInternal(new XtsMode(dataCrypto, tweakCrypto), iv, plain, cipher);
	}

	[Theory]
	[MemberData(nameof(Data2), MemberType = typeof(AESXTSTest))]
	public void Test(string keyHex, string ivHex, string plainHex, string cipherHex)
	{
		ReadOnlySpan<byte> key = keyHex.FromHex();
		ReadOnlySpan<byte> iv = ivHex.FromHex();
		ReadOnlySpan<byte> plain = plainHex.FromHex();
		ReadOnlySpan<byte> cipher = cipherHex.FromHex();

		ReadOnlySpan<byte> key1 = key.Slice(0, key.Length >> 1);
		ReadOnlySpan<byte> key2 = key.Slice(key.Length >> 1);

		using IBlockCrypto dataCrypto = AESUtils.CreateECB(key1);
		using IBlockCrypto tweakCrypto = AESUtils.CreateECB(key2);

		TestInternal(new XtsMode(dataCrypto, tweakCrypto), iv, plain, cipher);
	}
}
