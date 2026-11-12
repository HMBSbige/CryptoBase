#if NET11_0_OR_GREATER
using CryptoBase.Ciphers.Blocks.SM4;

namespace CryptoBase.Tests.Ciphers.Blocks.SM4;

public class SM4ArmTest
{
	[Before(Class)]
	public static void SkipWhenUnavailable()
	{
		Skip.Unless(SM4Arm.IsSupported, "The ARMv8.2 SM4 instructions are required.");
	}

	[Test]
	[Arguments(4)]
	[Arguments(8)]
	public Task PartialAndFullBatchesMatchIndependentReference(int width)
	{
		return SM4KernelTestUtils.BatchesMatchIndependentReference<SM4Arm>(width);
	}
}
#endif
