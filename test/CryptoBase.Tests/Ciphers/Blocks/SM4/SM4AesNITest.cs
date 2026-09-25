using CryptoBase.Ciphers.Blocks.SM4;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.Tests.Ciphers.Blocks.SM4;

public class SM4AesNITest
{
	[Before(Class)]
	public static void SkipWhenUnavailable()
	{
		if (!SM4AesNI.IsSupported)
		{
			Skip.Test("AES-NI and SSSE3 are required.");
		}
	}

	[Test]
	[Arguments(4)]
	[Arguments(8)]
	[Arguments(16)]
	public Task PartialAndFullBatchesMatchIndependentReference(int width)
	{
		return SM4KernelTestUtils.BatchesMatchIndependentReference<SM4AesNI>(width);
	}

	[Test]
	public Task Sbox128CoversEveryByteValueInEveryPosition()
	{
		return SM4KernelTestUtils.Substitute128MatchesIndependentReference(SM4AesNI.Substitute);
	}

	[Test]
	public Task Sbox256CoversEveryByteValueInEveryPosition()
	{
		if (!Avx2.IsSupported)
		{
			Skip.Test("AVX2 is required.");
		}

		return SM4KernelTestUtils.Substitute256MatchesIndependentReference(SM4AesNI.Substitute);
	}
}
