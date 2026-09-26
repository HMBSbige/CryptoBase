using CryptoBase.Ciphers.Blocks.SM4;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.Tests.Ciphers.Blocks.SM4;

public class SM4GfniTest
{
	[Before(Class)]
	public static void SkipWhenUnavailable()
	{
		if (!SM4Gfni.IsSupported)
		{
			Skip.Test("GFNI is required.");
		}
	}

	[Test]
	[Arguments(4)]
	[Arguments(8)]
	[Arguments(16)]
	[Arguments(32)]
	[Arguments(64)]
	public Task PartialAndFullBatchesMatchIndependentReference(int width)
	{
		return SM4KernelTestUtils.BatchesMatchIndependentReference<SM4Gfni>(width);
	}

	[Test]
	public Task Sbox128CoversEveryByteValueInEveryPosition()
	{
		return SM4KernelTestUtils.Substitute128MatchesIndependentReference(SM4Gfni.Substitute);
	}

	[Test]
	public Task Sbox256CoversEveryByteValueInEveryPosition()
	{
		if (!Gfni.V256.IsSupported)
		{
			Skip.Test("GFNI with 256-bit vectors is required.");
		}

		return SM4KernelTestUtils.Substitute256MatchesIndependentReference(SM4Gfni.Substitute);
	}

	[Test]
	public Task Sbox512CoversEveryByteValueInEveryPosition()
	{
		if (!Gfni.V512.IsSupported)
		{
			Skip.Test("GFNI with 512-bit vectors is required.");
		}

		return SM4KernelTestUtils.Substitute512MatchesIndependentReference(SM4Gfni.Substitute);
	}
}
