namespace CryptoBase.SpeedTest.Workloads;

internal sealed class SelfTestException(string message) : Exception(message)
{
	[DoesNotReturn]
	public static void Throw(string message)
	{
		throw new SelfTestException(message);
	}

	public static void ThrowIfFalse([DoesNotReturnIf(false)] bool condition, string message)
	{
		if (!condition)
		{
			Throw(message);
		}
	}

	public static void ThrowIfNotEqual(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual, string message)
	{
		ThrowIfFalse(expected.SequenceEqual(actual), message);
	}
}
