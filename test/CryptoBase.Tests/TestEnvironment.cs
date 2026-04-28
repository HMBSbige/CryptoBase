using System.Runtime.Intrinsics.X86;

namespace CryptoBase.Tests;

public class TestEnvironment
{
	public static bool TestLargeMessage => false;

	public static bool TestX86 => X86Base.IsSupported;

	/// <summary>
	/// https://github.com/dotnet/runtime/blob/main/src/coreclr/jit/jitconfigvalues.h
	/// </summary>
	[Test]
	public async Task IntrinsicDisableEnvironmentTest()
	{
		if (X86Base.IsSupported)
		{
			if (Environment.GetEnvironmentVariable("DOTNET_EnableHWIntrinsic") is "0")
			{
				await Assert.That(Sse2.IsSupported).IsFalse();
				await Assert.That(Avx.IsSupported).IsFalse();
				await Assert.That(Avx2.IsSupported).IsFalse();
				await Assert.That(Avx512F.IsSupported).IsFalse();
			}

			if (Environment.GetEnvironmentVariable("DOTNET_EnableAVX") is "0")
			{
				await Assert.That(Avx.IsSupported).IsFalse();
				await Assert.That(Avx2.IsSupported).IsFalse();
				await Assert.That(Avx512F.IsSupported).IsFalse();
			}

			if (Environment.GetEnvironmentVariable("DOTNET_EnableAVX512") is "0")
			{
				await Assert.That(Avx512F.IsSupported).IsFalse();
			}
		}
	}
}

public sealed class SkipLargeMessageAttribute() : SkipAttribute("Skip LargeMessage")
{
	public override Task<bool> ShouldSkip(TestRegisteredContext context)
	{
		return Task.FromResult(!TestEnvironment.TestLargeMessage);
	}
}

public sealed class RequiresX86Attribute() : SkipAttribute("X86")
{
	public override Task<bool> ShouldSkip(TestRegisteredContext context)
	{
		return Task.FromResult(!TestEnvironment.TestX86);
	}
}
