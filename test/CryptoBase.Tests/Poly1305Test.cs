using CryptoBase.Abstractions;
using CryptoBase.DataFormatExtensions;
using CryptoBase.Macs.Poly1305;

namespace CryptoBase.Tests;

public class Poly1305Test
{
	/// <summary>
	/// https://tools.ietf.org/html/rfc8439
	/// </summary>
	public static readonly TheoryData<string, string, string> Data = new()
	{
		{ @"85D6BE7857556D337F4452FE42D506A80103808AFB0DB2FD4ABFF6AF4149F51B", @"43727970746F6772617068696320466F72756D2052657365617263682047726F7570", @"c88886f51af32a75f0fdf57c4a7defdd" },
		{ @"746869732069732033322d62797465206b657920666f7220506f6c7931333035", @"48656c6c6f20776f726c6421", @"cf76f9033b46a114c8ba0577105cc8ed" },
		{ @"746869732069732033322d62797465206b657920666f7220506f6c7931333035", @"85D6BE7857556D337F4452FE42D506A80103808AFB0DB2FD4ABFF6AF4149F51B746869732069732033322d62797465206b657920666f7220506f6c793133303543727970746F6772617068696320466F72756D2052657365617263682047726F75708A438BDEE65C422A8366A2F85E5E93972FF925F667EB483EB01B1CD6C9", @"b0c63d86c91980a61c0824fb5cf618cc" },
		{ @"746869732069732033322d62797465206b657920666f7220506f6c7931333035", @"ec74691700388dace60b6a392f328c2b971b2f952b2a56a5604ac0b66e94bd4ef8a2c3b884cfa59ca342b2e3da53ec1d3b69b62c9a392687aaf55d95a1df6b0ad2c55bb64fc4802cc3feda602b6656a05b40b6e7ad2c55bb64f62882c85b0685353deb7f38cbb1ad69223dcc3457ae5b6b0dfa6bf4ded81d", @"c783ec8f3716299f4e74a76f4e03296b" }
	};

	private static void Test_Internal(IMac mac, string plainHex, string cipherHex)
	{
		Span<byte> plain = plainHex.FromHex();
		Span<byte> cipher = cipherHex.FromHex();
		Span<byte> o = stackalloc byte[mac.Length];

		Assert.Equal(@"Poly1305", mac.Name);
		Assert.Equal(16, mac.Length);

		mac.Update(plain);
		mac.GetMac(o);

		Assert.True(o.SequenceEqual(cipher));

		mac.Update(plain);
		mac.GetMac(o);

		Assert.True(o.SequenceEqual(cipher));

		mac.Update(plain);
		mac.Reset();

		mac.Update(plain);
		mac.GetMac(o);

		Assert.True(o.SequenceEqual(cipher));

		mac.Dispose();
	}

	[Theory]
	[MemberData(nameof(Data), MemberType = typeof(Poly1305Test))]
	public void Test(string keyHex, string plainHex, string cipherHex)
	{
		byte[] key = keyHex.FromHex();
		Test_Internal(new Poly1305SF(key), plainHex, cipherHex);
		Test_Internal(Poly1305Utils.Create(key), plainHex, cipherHex);
	}

	[Theory(Skip = "X86", SkipUnless = nameof(TestEnvironment.TestX86), SkipType = typeof(TestEnvironment))]
	[MemberData(nameof(Data), MemberType = typeof(Poly1305Test))]
	public void TestX86(string keyHex, string plainHex, string cipherHex)
	{
		byte[] key = keyHex.FromHex();
		Test_Internal(new Poly1305X86(key), plainHex, cipherHex);
	}
}
