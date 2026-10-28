using CryptoBase.Ciphers.Blocks.SM4;
using System.Runtime.Intrinsics;

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
	public Task SboxCoversEveryByteValueInEveryPosition()
	{
		return SM4KernelTestUtils.SubstituteMatchesIndependentReference<Vector128<byte>>(SM4AesNI.Substitute);
	}
}
