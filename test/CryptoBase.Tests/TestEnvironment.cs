using System.Runtime.Intrinsics.X86;

namespace CryptoBase.Tests;

public static class TestEnvironment
{
	public static bool TestLargeMessage => false;

	public static bool TestX86 => X86Base.IsSupported;
}
