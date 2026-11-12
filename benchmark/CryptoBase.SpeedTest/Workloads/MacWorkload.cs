namespace CryptoBase.SpeedTest.Workloads;

internal sealed class MacWorkload<T>(int inputSize, int keySize) : Workload where T : IOneShotMacAlgorithm
{
	private readonly byte[] _key = TestData.Sequence(keySize);
	private readonly byte[] _source = TestData.Random(inputSize);
	private readonly byte[] _mac = new byte[T.MacLength];

	public override void Verify()
	{
		int length = T.Mac(_key, _source, _mac);
		SelfTestException.ThrowIfFalse(length == T.MacLength, "Mac returned a wrong length.");
		MacChecks.Verify(_mac, (key, mac) => T.Mac(key, _source, mac), _key);
	}

	public override void Run(long iterations)
	{
		Mac<T>(_key, _source, _mac, iterations);
	}

	private static void Mac<TMac>(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> mac, long iterations) where TMac : IOneShotMacAlgorithm
	{
		for (long i = 0; i < iterations; ++i)
		{
			TMac.Mac(key, source, mac);
		}
	}
}

/// <summary>
/// Computes a MAC that a static method other than <see cref="IOneShotMacAlgorithm.Mac" /> provides, such as KMAC with its customization string.
/// </summary>
internal sealed class MacFunctionWorkload(int inputSize, int keySize, int macLength, MacFunction function) : Workload
{
	private readonly byte[] _key = TestData.Sequence(keySize);
	private readonly byte[] _source = TestData.Random(inputSize);
	private readonly byte[] _mac = new byte[macLength];

	public override void Verify()
	{
		function(_key, _source, _mac, default);
		MacChecks.Verify(_mac, (key, mac) => function(key, _source, mac, default), _key);
	}

	public override void Run(long iterations)
	{
		ReadOnlySpan<byte> key = _key;
		ReadOnlySpan<byte> source = _source;
		Span<byte> mac = _mac;

		for (long i = 0; i < iterations; ++i)
		{
			function(key, source, mac, default);
		}
	}
}

internal delegate void MacFunction(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination, ReadOnlySpan<byte> customization);

file static class MacChecks
{
	public delegate void Compute(byte[] key, byte[] mac);

	public static void Verify(byte[] mac, Compute compute, byte[] key)
	{
		byte[] again = new byte[mac.Length];
		compute(key, again);
		SelfTestException.ThrowIfNotEqual(mac, again, "The MAC is not deterministic.");

		byte[] otherKey = [.. key];
		otherKey[0] ^= 1;
		compute(otherKey, again);
		SelfTestException.ThrowIfFalse(!mac.AsSpan().SequenceEqual(again), "The MAC does not depend on the key.");
	}
}
