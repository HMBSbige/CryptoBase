using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.AEADCryptos;
using CryptoBase.DataFormatExtensions;
using CryptoBase.SymmetricCryptos.AEADCryptos;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptoBase.Tests;

[TestClass]
public class ChaCha20Poly1305Test
{
	private static void Test(IAEADCrypto crypto, string nonceHex, string associatedDataHex, string tagHex, string plainHex, string cipherHex)
	{
		Assert.AreEqual(@"ChaCha20-Poly1305", crypto.Name);

		ReadOnlySpan<byte> nonce = nonceHex.FromHex();
		ReadOnlySpan<byte> associatedData = associatedDataHex.FromHex();
		ReadOnlySpan<byte> tag = tagHex.FromHex();
		ReadOnlySpan<byte> plain = plainHex.FromHex();
		ReadOnlySpan<byte> cipher = cipherHex.FromHex();
		Span<byte> o1 = stackalloc byte[plain.Length];
		Span<byte> o2 = stackalloc byte[16];

		crypto.Encrypt(nonce, plain, o1, o2, associatedData);
		Assert.IsTrue(o1.SequenceEqual(cipher));
		Assert.IsTrue(o2.SequenceEqual(tag));

		crypto.Encrypt(nonce, plain, o1, o2, associatedData);
		Assert.IsTrue(o1.SequenceEqual(cipher));
		Assert.IsTrue(o2.SequenceEqual(tag));

		crypto.Decrypt(nonce, cipher, tag, o1, associatedData);
		Assert.IsTrue(o1.SequenceEqual(plain));

		crypto.Decrypt(nonce, cipher, tag, o1, associatedData);
		Assert.IsTrue(o1.SequenceEqual(plain));

		crypto.Dispose();
	}

	/// <summary>
	/// https://tools.ietf.org/html/rfc8439
	/// </summary>
	[TestMethod]
	[DataRow(@"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F", @"070000004041424344454647", @"50515253C0C1C2C3C4C5C6C7",
		@"1AE10B594F09E26A7E902ECBD0600691",
		@"4C616469657320616E642047656E746C656D656E206F662074686520636C617373206F66202739393A204966204920636F756C64206F6666657220796F75206F6E6C79206F6E652074697020666F7220746865206675747572652C2073756E73637265656E20776F756C642062652069742E",
		@"D31A8D34648E60DB7B86AFBC53EF7EC2A4ADED51296E08FEA9E2B5A736EE62D63DBEA45E8CA9671282FAFB69DA92728B1A71DE0A9E060B2905D6A5B67ECD3B3692DDBD7F2D778B8C9803AEE328091B58FAB324E4FAD675945585808B4831D7BC3FF4DEF08E4B7A9DE576D26586CEC64B6116")]
	[DataRow(@"1C9240A5EB55D38AF333888604F6B5F0473917C1402B80099DCA5CBC207075C0", @"000000000102030405060708", @"F33388860000000000004E91",
		@"EEAD9D67890CBB22392336FEA1851F38",
		@"496E7465726E65742D4472616674732061726520647261667420646F63756D656E74732076616C696420666F722061206D6178696D756D206F6620736978206D6F6E74687320616E64206D617920626520757064617465642C207265706C616365642C206F72206F62736F6C65746564206279206F7468657220646F63756D656E747320617420616E792074696D652E20497420697320696E617070726F70726961746520746F2075736520496E7465726E65742D447261667473206173207265666572656E6365206D6174657269616C206F7220746F2063697465207468656D206F74686572207468616E206173202FE2809C776F726B20696E2070726F67726573732E2FE2809D",
		@"64A0861575861AF460F062C79BE643BD5E805CFD345CF389F108670AC76C8CB24C6CFC18755D43EEA09EE94E382D26B0BDB7B73C321B0100D4F03B7F355894CF332F830E710B97CE98C8A84ABD0B948114AD176E008D33BD60F982B1FF37C8559797A06EF4F0EF61C186324E2B3506383606907B6A7C02B0F9F6157B53C867E4B9166C767B804D46A59B5216CDE7A4E99040C5A40433225EE282A1B0A06C523EAF4534D7F83FA1155B0047718CBC546A0D072B04B3564EEA1B422273F548271A0BB2316053FA76991955EBD63159434ECEBB4E466DAE5A1073A6727627097A1049E617D91D361094FA68F0FF77987130305BEABA2EDA04DF997B714D6C6F2C29A6AD5CB4022B02709B")]
	public void Test(string keyHex, string nonceHex, string associatedDataHex, string tagHex, string plainHex, string cipherHex)
	{
		byte[] key = keyHex.FromHex();
		Test(new BcChaCha20Poly1305Crypto(key), nonceHex, associatedDataHex, tagHex, plainHex, cipherHex);
		Test(new DefaultChaCha20Poly1305Crypto(key), nonceHex, associatedDataHex, tagHex, plainHex, cipherHex);
		Test(new ChaCha20Poly1305Crypto(key), nonceHex, associatedDataHex, tagHex, plainHex, cipherHex);
		Test(AEADCryptoCreate.ChaCha20Poly1305(key), nonceHex, associatedDataHex, tagHex, plainHex, cipherHex);
	}
}
