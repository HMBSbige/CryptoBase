using CryptoBase.Abstractions;
using CryptoBase.DataFormatExtensions;
using CryptoBase.Macs.GHash;
using System.Security.Cryptography;

namespace CryptoBase.Tests;

public class GHashTest
{
	/// <summary>
	/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
	/// https://www.intel.cn/content/dam/www/public/us/en/documents/white-papers/carry-less-multiplication-instruction-in-gcm-mode-paper.pdf
	/// </summary>
	public static IEnumerable<(string, string, string)> Data =>
	[
		(@"dfa6bf4ded81db03ffcaff95f830f061", @"952b2a56a5604ac0b32b6656a05b40b6", @"da53eb0ad2c55bb64fc4802cc3feda60"),
		(@"66e94bd4ef8a2c3b884cfa59ca342b2e", @"", @"00000000000000000000000000000000"),
		(@"66e94bd4ef8a2c3b884cfa59ca342b2e", @"0388dace60b6a392f328c2b971b2fe78", @"5e2ec746917062882c85b0685353deb7"),
		(@"66e94bd4ef8a2c3b884cfa59ca342b2e", @"0388dace60b6a392f328c2b971b2fe7800000000000000000000000000000080", @"f38cbb1ad69223dcc3457ae5b6b0f885"),
		(@"66e94bd4ef8a2c3b884cfa59ca342b2e", @"0388dace60b6a392f328c2b971b2fe7ad2c55bb64f", @"c1d3b69b62c9a392687aaf55d95a1df6")
	];

	private static async Task Test_Internal(IMac mac, string plainHex, string cipherHex)
	{
		byte[] plain = plainHex.FromHex();

		byte[] cipher = cipherHex.FromHex();

		byte[] o = new byte[mac.Length];

		await Assert.That(mac.Name).IsEqualTo(@"GHash");
		await Assert.That(mac.Length).IsEqualTo(16);

		mac.Update(plain);
		mac.GetMac(o);

		await Assert.That(cipher.SequenceEqual(o)).IsTrue();

		mac.Update(plain);
		mac.GetMac(o);

		await Assert.That(cipher.SequenceEqual(o)).IsTrue();

		mac.Update(plain);
		mac.Reset();

		mac.Update(plain);
		mac.GetMac(o);

		await Assert.That(cipher.SequenceEqual(o)).IsTrue();

		mac.Dispose();
	}

	[Test]
	[MethodDataSource(nameof(Data))]
	public async Task Test(string keyHex, string plainHex, string cipherHex)
	{
		byte[] key = keyHex.FromHex();
		await Test_Internal(new GHashSF(key), plainHex, cipherHex);
		await Test_Internal(GHashUtils.Create(key), plainHex, cipherHex);
	}

	[Test]
	[RequiresX86]
	[MethodDataSource(nameof(Data))]
	public async Task TestX86(string keyHex, string plainHex, string cipherHex)
	{
		byte[] key = keyHex.FromHex();
		await Test_Internal(new GHashX86(key), plainHex, cipherHex);
	}

	[Test]
	[Arguments(4 - 1)]
	[Arguments(8 - 1)]
	[Arguments(16 - 1)]
	[Arguments(32 - 1)]
	[Arguments(64 - 1)]
	[Arguments(128 - 1)]
	[Arguments(256 - 1)]
	public async Task TestBlocks(int n)
	{
		const int blockSize = 16;
		using IMac mac = GHashUtils.Create(RandomNumberGenerator.GetBytes(16));
		byte[] expected = new byte[blockSize];

		byte[] blocks = RandomNumberGenerator.GetBytes(n * blockSize + 1);

		for (int i = 0; i < n; ++i)
		{
			mac.Update(blocks.AsSpan().Slice(i * blockSize, blockSize));
		}

		mac.Update(blocks.AsSpan().Slice(n * blockSize));

		mac.GetMac(expected);

		mac.Update(blocks);

		byte[] actual = new byte[blockSize];

		mac.GetMac(actual);

		await Assert.That(expected.SequenceEqual(actual)).IsTrue();
	}
}
