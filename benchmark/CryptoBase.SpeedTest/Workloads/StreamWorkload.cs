namespace CryptoBase.SpeedTest.Workloads;

/// <summary>
/// XORs a buffer of a fixed size with the keystream of one continuing <see cref="IStreamCipher" /> instance.
/// </summary>
/// <remarks>
/// A stream cipher refuses to run past the end of its counter, which for ChaCha20 with a 96-bit nonce comes after 256 GiB.
/// The workload therefore replaces its instance, outside the inner loop, after every <see cref="BytesPerInstance" /> bytes.
/// </remarks>
internal sealed class StreamWorkload<T>(int inputSize, Func<T> factory) : Workload where T : class, IStreamCipher
{
	private const long BytesPerInstance = 16L << 30;

	private readonly byte[] _source = TestData.Random(inputSize);
	private readonly byte[] _destination = new byte[inputSize];
	private readonly long _iterationsPerInstance = GetIterationsPerInstance(inputSize);
	private T _cipher = factory();
	private long _iterationsLeft = GetIterationsPerInstance(inputSize);

	public override void Verify()
	{
		byte[] decrypted = new byte[_source.Length];

		using (T encryptor = factory())
		{
			encryptor.Xor(_source, _destination);
		}

		using (T decryptor = factory())
		{
			decryptor.Xor(_destination, decrypted);
		}

		SelfTestException.ThrowIfFalse(_source.Length < 16 || !_source.AsSpan().SequenceEqual(_destination), "The keystream is zero.");
		SelfTestException.ThrowIfNotEqual(_source, decrypted, "Decryption did not restore the plaintext.");
	}

	public override void Run(long iterations)
	{
		ReadOnlySpan<byte> source = _source;
		Span<byte> destination = _destination;

		while (iterations > 0)
		{
			if (_iterationsLeft is 0)
			{
				_cipher.Dispose();
				_cipher = factory();
				_iterationsLeft = _iterationsPerInstance;
			}

			long count = Math.Min(iterations, _iterationsLeft);
			T cipher = _cipher;

			for (long i = 0; i < count; ++i)
			{
				cipher.Xor(source, destination);
			}

			iterations -= count;
			_iterationsLeft -= count;
		}
	}

	public override void Dispose()
	{
		_cipher.Dispose();
	}

	private static long GetIterationsPerInstance(int inputSize)
	{
		return Math.Max(1, BytesPerInstance / inputSize);
	}
}
