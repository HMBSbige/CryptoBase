using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.DataFormatExtensions;
using CryptoBase.Digests.SM3;
using System.Text;

namespace CryptoBase.Tests;

public class SM3Test
{
	private static async Task SM3DigestTest_Internal(IHash sm3, string str, string sm3Str)
	{
		await Assert.That(sm3.Name).IsEqualTo(@"SM3");
		await Assert.That(sm3.Length).IsEqualTo(32);
		await Assert.That(sm3.BlockSize).IsEqualTo(64);

		byte[] origin = Encoding.UTF8.GetBytes(str);

		byte[] hash = new byte[sm3.Length];

		sm3.UpdateFinal(origin, hash);
		sm3.UpdateFinal(origin, hash);

		await Assert.That(sm3Str.SequenceEqual(hash.ToHex())).IsTrue();

		sm3.Update(origin);
		sm3.GetHash(hash);

		await Assert.That(sm3Str.SequenceEqual(hash.ToHex())).IsTrue();

		sm3.Update(origin);
		sm3.Reset();

		sm3.Update(origin.AsSpan().Slice(0, origin.Length / 2));
		sm3.Update(origin.AsSpan().Slice(origin.Length / 2));
		sm3.GetHash(hash);

		await Assert.That(sm3Str.SequenceEqual(hash.ToHex())).IsTrue();

		sm3.Update(origin.AsSpan().Slice(0, origin.Length / 2));
		sm3.UpdateFinal(origin.AsSpan().Slice(origin.Length / 2), hash);

		await Assert.That(sm3Str.SequenceEqual(hash.ToHex())).IsTrue();

		sm3.Dispose();
	}

	/// <summary>
	/// https://gchq.github.io/CyberChef/#recipe=SM3(256,64)
	/// </summary>
	[Test]
	[Arguments(@"", @"1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b")]
	[Arguments(@"abc", @"66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")]
	[Arguments(@"abcde", @"afe4ccac5ab7d52bcae36373676215368baf52d3905e1fecbe369cc120e97628")]
	[Arguments(@"abcdez", @"897671415764167c85037e3bba4cc0f8fa019accd94730f0188b5c74bc502912")]
	[Arguments(@"d60e1c2860a249ddb96ddfebbb618a53daa635b1c504409c935ffab4", @"ab00404a6acb46f48ee28b42354ce984adb2e19b11a4675a5a043f62506fe117")]
	[Arguments(@"d60e1c2860a249ddb96ddfebbb618a53daa635b1c504409c935ffab41a0d", @"2b9bdd2ffbe3f293744af51b181cdb36a6bf0d5065306a56a7b8c5a5cb2e03d1")]
	[Arguments(@"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", @"debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732")]
	[Arguments(@"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", @"f07b76f62b616de94e6ef9733db1953b8e3fa55014c3f4667abf2ea60aa44250")]
	public async Task SM3DigestTest(string str, string sm3Str)
	{
		await SM3DigestTest_Internal(new BcSM3Digest(), str, sm3Str);
		await SM3DigestTest_Internal(new SM3Digest(), str, sm3Str);
	}

	[Test]
	[SkipLargeMessage]
	[Arguments(@"euasxpm", @"de27a8b04cf2bde6c963fc0d8df4fdceee26f03a9f0d1ff80e5773817444f172")]
	public async Task LargeMessageTest(string str, string result)
	{
		await TestUtils.LargeMessageTest(new BcSM3Digest(), str, result);
		await TestUtils.LargeMessageTest(new SM3Digest(), str, result);
	}
}
