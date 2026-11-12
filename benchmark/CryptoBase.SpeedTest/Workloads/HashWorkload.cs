namespace CryptoBase.SpeedTest.Workloads;

internal sealed class HashWorkload<T>(int inputSize) : Workload where T : class, IHashAlgorithm<T>
{
	private readonly byte[] _source = TestData.Random(inputSize);
	private readonly byte[] _hash = new byte[T.HashLength];

	public override void Verify()
	{
		int length = T.HashData(_source, _hash);
		SelfTestException.ThrowIfFalse(length == T.HashLength, "HashData returned a wrong length.");

		byte[] incremental = new byte[T.HashLength];
		using T hash = T.Create();
		int half = _source.Length / 2;
		hash.Append(_source.AsSpan(0, half));
		hash.Append(_source.AsSpan(half));
		hash.GetHashAndReset(incremental);

		SelfTestException.ThrowIfNotEqual(incremental, _hash, "The one-shot hash differs from the incremental hash.");
	}

	public override void Run(long iterations)
	{
		HashData<T>(_source, _hash, iterations);
	}

	private static void HashData<THash>(ReadOnlySpan<byte> source, Span<byte> hash, long iterations) where THash : class, IHashAlgorithm<THash>
	{
		for (long i = 0; i < iterations; ++i)
		{
			THash.HashData(source, hash);
		}
	}
}
