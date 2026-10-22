using TUnit.Core.Interfaces;

namespace CryptoBase.Tests.Kdf.Argon2;

// Beside the other tests, a 32-bit process often has address space for only one or two 64 MiB memories, so it runs these tests one at a time.
[AttributeUsage(AttributeTargets.Method)]
internal sealed class Argon2LargeMemoryAttribute : Attribute, ITestRegisteredEventReceiver, IParallelLimit
{
	public int Limit => 1;

	public ValueTask OnTestRegistered(TestRegisteredContext context)
	{
		if (!Environment.Is64BitProcess)
		{
			context.SetParallelLimiter(this);
		}

		return ValueTask.CompletedTask;
	}
}
