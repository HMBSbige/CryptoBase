using CryptoBase.Ciphers.Blocks.SM4;

namespace CryptoBase.Tests.Ciphers.Blocks.SM4;

public class SM4ArmAesTest
{
	[Before(Class)]
	public static void SkipWhenUnavailable()
	{
		if (!SM4ArmAes.IsSupported)
		{
			Skip.Test("ARM64 AES is required.");
		}
	}

	[Test]
	[Arguments(4)]
	[Arguments(8)]
	public Task PartialAndFullBatchesMatchIndependentReference(int width)
	{
		return SM4KernelTestUtils.BatchesMatchIndependentReference<SM4ArmAes>(width);
	}

	[Test]
	public Task SboxCoversEveryByteValueInEveryPosition()
	{
		return SM4KernelTestUtils.Substitute128MatchesIndependentReference(SM4ArmAes.Substitute);
	}
}
