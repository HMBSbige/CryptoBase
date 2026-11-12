namespace CryptoBase.SpeedTest.Workloads;

/// <summary>
/// Derives key material from <paramref name="secret" /> into <paramref name="output" />, with any other inputs fixed by the function.
/// </summary>
internal delegate void KdfFunction(ReadOnlySpan<byte> secret, Span<byte> output);

internal sealed class KdfWorkload(int secretLength, int outputLength, KdfFunction derive) : Workload
{
	private readonly byte[] _secret = TestData.Random(secretLength);
	private readonly byte[] _output = new byte[outputLength];

	public override void Verify()
	{
		byte[] expected = new byte[outputLength];
		derive(_secret, expected);
		derive(_secret, _output);
		SelfTestException.ThrowIfNotEqual(expected, _output, "The derivation is not deterministic.");

		byte[] otherSecret = [.. _secret];
		otherSecret[0] ^= 1;
		derive(otherSecret, _output);
		SelfTestException.ThrowIfFalse(!expected.AsSpan().SequenceEqual(_output), "The output does not depend on the secret.");
	}

	public override void Run(long iterations)
	{
		KdfFunction function = derive;
		ReadOnlySpan<byte> secret = _secret;
		Span<byte> output = _output;

		for (long i = 0; i < iterations; ++i)
		{
			function(secret, output);
		}
	}
}
