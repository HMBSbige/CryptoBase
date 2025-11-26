using System.Runtime.Intrinsics.X86;

namespace CryptoBase.Tests;

public class TestEnvironment
{
	public static bool TestLargeMessage => false;

	public static bool TestX86 => X86Base.IsSupported;

	/// <summary>
	/// https://github.com/dotnet/runtime/blob/main/src/coreclr/jit/jitconfigvalues.h
	/// </summary>
	[Fact]
	public void IntrinsicDisableEnvironmentTest()
	{
		Assert.False(System.Runtime.GCSettings.IsServerGC);

		if (X86Base.IsSupported)
		{
			if (Environment.GetEnvironmentVariable("DOTNET_EnableHWIntrinsic") is "0")
			{
				Assert.False(Sse2.IsSupported);
				Assert.False(Avx.IsSupported);
				Assert.False(Avx2.IsSupported);
				Assert.False(Avx512F.IsSupported);
			}

			if (Environment.GetEnvironmentVariable("DOTNET_EnableAVX") is "0")
			{
				Assert.False(Avx.IsSupported);
				Assert.False(Avx2.IsSupported);
				Assert.False(Avx512F.IsSupported);
			}

			if (Environment.GetEnvironmentVariable("DOTNET_EnableAVX512") is "0")
			{
				Assert.False(Avx512F.IsSupported);
			}
		}
	}
}
