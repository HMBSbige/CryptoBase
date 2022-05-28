using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;
using CryptoBase.DataFormatExtensions;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;
using CryptoBase.SymmetricCryptos.StreamCryptos;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;

namespace CryptoBase.Tests;

[TestClass]
public class SM4Test
{
	private static void Test(IBlockCrypto crypto, string hex1, string hex2, string hex3)
	{
		Assert.AreEqual(@"SM4", crypto.Name);
		Assert.AreEqual(16, crypto.BlockSize);

		Span<byte> h1 = hex1.FromHex();
		Span<byte> h2 = hex2.FromHex();
		Span<byte> h3 = hex3.FromHex();
		Span<byte> o1 = new byte[crypto.BlockSize];

		crypto.Encrypt(h1, o1);
		Assert.IsTrue(o1.SequenceEqual(h2));

		crypto.Encrypt(h1, o1);
		Assert.IsTrue(o1.SequenceEqual(h2));

		Span<byte> t = h1;
		for (int i = 0; i < 1000000; ++i)
		{
			crypto.Encrypt(t, o1);
			t = o1;
		}

		Assert.IsTrue(t.SequenceEqual(h3));

		crypto.Decrypt(h2, o1);
		Assert.IsTrue(o1.SequenceEqual(h1));

		crypto.Decrypt(h2, o1);
		Assert.IsTrue(o1.SequenceEqual(h1));

		t = h3;
		for (int i = 0; i < 1000000; ++i)
		{
			crypto.Decrypt(t, o1);
			t = o1;
		}
		Assert.IsTrue(t.SequenceEqual(h1));

		crypto.Dispose();
	}

	private static void TestN(int n, IBlockCrypto crypto, ReadOnlySpan<byte> key)
	{
		using SM4Crypto sf = new(key);
		ReadOnlySpan<byte> source = RandomNumberGenerator.GetBytes(n * sf.BlockSize);
		Span<byte> expected = stackalloc byte[source.Length];

		for (int i = 0; i < n; ++i)
		{
			sf.Encrypt(source.Slice(i * sf.BlockSize, sf.BlockSize), expected.Slice(i * sf.BlockSize, sf.BlockSize));
		}

		Assert.AreEqual(@"SM4", crypto.Name);
		Assert.AreEqual(n * sf.BlockSize, crypto.BlockSize);

		Span<byte> destination = stackalloc byte[source.Length];

		crypto.Encrypt(source, destination);

		Assert.IsTrue(expected.SequenceEqual(destination));

		crypto.Dispose();
	}

	[TestMethod]
	[DataRow(@"0123456789ABCDEFFEDCBA9876543210", @"0123456789ABCDEFFEDCBA9876543210", @"681EDF34D206965E86B3E94F536E4246", @"595298C7C6FD271F0402F804C33D3F66")]
	public void Test(string keyHex, string hex1, string hex2, string hex3)
	{
		byte[] key = keyHex.FromHex();
		Test(new BcSM4Crypto(default, key), hex1, hex2, hex3);
		Test(new SM4Crypto(key), hex1, hex2, hex3);
	}

	[TestMethod]
	public void TestN()
	{
		ReadOnlySpan<byte> key = RandomNumberGenerator.GetBytes(16);
		TestN(4, new SM4CryptoX86(key), key);
		if (Avx.IsSupported)
		{
			TestN(8, new SM4CryptoBlock8X86(key), key);
			TestN(16, new SM4CryptoBlock16X86(key), key);
		}
	}

	/// <summary>
	/// https://gchq.github.io/CyberChef/#recipe=SM4_Encrypt(%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D,'CTR','Hex','Hex')Remove_whitespace(true,true,true,true,true,false)To_Upper_case('All')
	/// </summary>
	[TestMethod]
	[DataRow(
		@"B7FAD2F367B9999C95E207CA2E16616D",
		@"CBD328D0C128002C6A44384590E6DBC9",
		@"5B0C121AD672AAFF1009FC4294584AED651748C3E15765834A914755DC7D7FDCE7E1EDB7C821570AA9199E9C923CC4AEF36E1D270DE0BE2CC70E81A981B4369ACB7DE3F664C6AFE437C069BE43C56655D3D614D5B55BEFEDAA2C42A7F88B88F00557862671DB8E1CA7D6826D308C537C2AFCC253DF349C4F8F41C1B115068767A16A39FABB0D3041BE4C3F75BA146806B056290B90BA146A91DCB6C00AFFD9AAA873FE55C75D93F1314ED91D99BED6D3837243DF08E9C0F1984176500CA4959E660CC9A99FE0541D0155C9BC8356419411557FCB1FDD0277B72F5DA8580E10CD168FA177D8067E67C0858B4D599568219B39929A553380C46B525EFC8B3A844CC9ED8D554C382AB6CDCB94EEDE0E46E846CC84EBE35585C19053E469F5280C05493361C978BCF1A1535A8482FA468941C6ACA84B07B9603F4CD95ED7B7DB1B29923C651BED6073480AEF57B41E6344B91A06ADF36E8FABF0F410B210C6D1B56AF843FFE3FF6E09631A02EC4D46BDB0D73DBBFD82620D67D2A5608979BC754C86C77E871C577D244968F83A0173FD453B0C2C6F2CE6109245214F918CD4B349AFE73D4B4CD18751C6FB3C15E6742AB23BEC713222AC2948B83B741B0478009ABEC3A774D51E5331F96D6CBDBABF5170D8A2B5B2CCC26C3544711E4E9D801BBAF1EF6D3FFCA0E5AFE1A0F96C267F42308DEECFCBAABF647F756429F274B99F4C",
		@"B4632B189DF350F6D21C143B6CC7D0A29392FB0FF92410FB231669CA43E1BCFB6348CF02EAB1DFB0CB6349329C7CF4F5CEF1336B990DC087C5165652DE22C731D4383D1753C5E257535B93E7EBD348187F99FB1852AA2D8C83ACC41375E2BAA324F5C8E0BBD180E68DB60D18FB873D85AB97E474518455F0BAE22BF561972A8072D9A5E5B983472B632639002A8C6748AB5E07E6B7B429FFA51FAE55ED4080690A3C05FD0C5FD5C969F5A9316582C8762BF9AF9040DA28596E880AF78676A82375AAC304088847AC1F162C5D6304F8D11E9C52B29476915ED45742C42344711567C1A4E46216CE83FFEDFB409E49919FA920F6EBC011ED9B0B3649C348E9F7F9187A798FFEBBCEE37E7F07E2B45E7E992A2A083074C3B82E71476FE219B52EE1FF4DD9196557B39E6EA0B2F27B3DB59089DF37B5DEFBC4A54A66C4A763AF9EBD7F88EFBC17AB5E066FC4D3AA13FB675CCA62EB321EA91C521B3D59FBF992A93609A61C03D1AEA3356E0D6BD9E5D59777B771E6BA1FC185027AB57E3B0A5F63D9C5943F5C91381B29C31719102FFDC48FF044AF9DD2A60D81D91CF2130F6D36D61964113FD1B56D92E308B2A61DF1021178F74CD799C1EAEB560D203F1242EECB84F760F4B81BC268022CD761D474097F1637AF97C77BAF9BC8FF02F5C5584FDB5675312193988CEF6E87C2A70A3BBBC606D8731E5F4746CCCFC39BEA26F482")]
	[DataRow(
		@"91602034DB05CDF2F47C023F7EB30DAE",
		@"B934FD1AAE4012AB34031BEEFC06E631",
		@"0A34E9DCA4BD7E3EC3869630CAB3804872E1F0A5F186521FEB47AB062C45F6CF6D734BD542AAAA4000C5E4F5364071D33C65032A59EC1899BBBA9F8AED65ABC262AFDA051263CA413EF8C95781B8BFBEACB2675FBE0A67B452B82E3D974C7D2E97B07DD46C90B9966E2CEAE792B09F4F5B92BE2D74D6EA7D78FDEBAB650317575B93808EFAE10A13D63EB482C9E0A75A137D6EB39FBA5D161BB9B50E8E685CCE1A62D3BF7216B1BBBE76EE9798F15DC92480829E70823051FAB8211E3581E07314E9FFAA2A046A4B6630D5C36C69CC1CB93BF934DA4B4A240D646D4642EB148E24054FB05C9D6F3687BC3915A2F0011827A1150A13CD6C6958117F78EB814864550EB9BE07C86A1E009CF464CEB64B91E9EB28051AB776494715E44875E5DF5F6CE87E7D320ED37D8898ED7DAE97EED7B5C473F4D0602F3EF730CD579CF36172B4081E88052778FC22D04D21F2FE5D444791FE0B6C53B11957C8FD06C1ABACCB9BED52CE7EE9C977C1FBB8423BD1DA6D6BEE72427D3321221DC1762BB9A3DD4D6E245BEA8EB4932A2C2560782508C495B807D2001396B0A073D7C9D83C72E152C260EFA844F5C323F08005590B0EF96A547512D618EA2C01EFDEDEA601B5B97D7137D7A2A9C355F2A47600472C41CF2A95CE2C4E4B35497FB4E9E2472244E5189F5A54EC55B15E93752522257027D9566F2B70D28E59AC03423B8AC9247D69",
		@"F87F4FDAFD47B9ED17190A0496D252F71648879F5ED32BEF116817E77C8738C74B5DF066E76F50849FCDEE23CE33AF0271E6A5369DA0CC46C1FA930591E3041827F44A2E19728FA0AE3E93372970299FF8A9C7D57255EBD416851CF042E6852B79F3594380CB7874A918FA2FB3B215629B7F6DF38838D60B654366EA1149182620F7FD491E0793E80D49F3A97A9B11596612F0CFB2B9B66C8B860C423F95602F428F1674A216C5127CD819BD3CF401CB3FEA6F45DA7901EB40A1F25A9FF2879368E9CBA54746FEE76FA07EAC9B71D3AEC646DFC31045C74B8D1FFC525686BC1E2AB23CB556AB038BA6DD6CA786669F55CA1E85CF8671F4D59CD5EE208A527EF18C342740A14EE991BBBCB49640C20BFA4E1BDF710F5CC4D6CD0B0C80A05439097677863BEE4F95B7627D3B7770727DB6FD7A9CB6C475E0E65B5C00DDDFC35F0FFBBFAEAA4EE4E31E583673FD0346168542E3C7C8B8DC00CA35BA17D1D52BE38CE4B2CAE96038FC3D0C3D40D1C086601B5097D3C43AB7031FC8301324A08253940A4E016089255977D6CA42CEF380B407621512281B8A1E4EF3C8F8B3B5BB44498DAEE1A60A07E1A990FF7FF78815F6F7EE811C80CC6FF9E70F13047DC7D090CCA74281B363BF5CBC1A146E8A1D88E630F9BB76B6F384221FF5B4692C9CEE8240D325D45A3D0E69843FEA3F3FC00A5F0BC31A42DF9BAB933A98058A8D5C8002")]
	public void TestCtr(string keyHex, string ivHex, string sourceHex, string expectedHex)
	{
		IStreamCrypto ctr = StreamCryptoCreate.Sm4Ctr(keyHex.FromHex(), ivHex.FromHex());
		Assert.AreEqual(@"SM4-CTR", ctr.Name);

		ReadOnlySpan<byte> source = sourceHex.FromHex();
		ReadOnlySpan<byte> expected = expectedHex.FromHex();
		Span<byte> destination = new byte[source.Length];

		ctr.Update(source, destination);

		Assert.IsTrue(destination.SequenceEqual(expected));
	}
}