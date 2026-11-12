namespace CryptoBase.SpeedTest.Workloads;

internal sealed class XofWorkload<T>(int inputSize, int outputLength) : Workload where T : class, IXof<T>
{
	private readonly byte[] _source = TestData.Random(inputSize);
	private readonly byte[] _output = new byte[outputLength];

	public override void Verify()
	{
		T.HashData(_source, _output);

		byte[] incremental = new byte[_output.Length];
		using T xof = T.Create();
		int half = _source.Length / 2;
		xof.Append(_source.AsSpan(0, half));
		xof.Append(_source.AsSpan(half));
		int firstRead = incremental.Length / 3;
		xof.Read(incremental.AsSpan(0, firstRead));
		xof.Read(incremental.AsSpan(firstRead));

		SelfTestException.ThrowIfNotEqual(incremental, _output, "The one-shot output differs from the incremental output.");
	}

	public override void Run(long iterations)
	{
		HashData<T>(_source, _output, iterations);
	}

	private static void HashData<TXof>(ReadOnlySpan<byte> source, Span<byte> output, long iterations) where TXof : class, IXof<TXof>
	{
		for (long i = 0; i < iterations; ++i)
		{
			TXof.HashData(source, output);
		}
	}
}
