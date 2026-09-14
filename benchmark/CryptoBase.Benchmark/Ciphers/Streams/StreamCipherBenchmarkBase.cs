using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Ciphers;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Ciphers.Streams;

public abstract class StreamCipherBenchmarkBase
{
	[ParamsSource(nameof(ByteLengths))]
	public int ByteLength { get; set; }

	public virtual IEnumerable<int> ByteLengths => [63, 64, 65, 256, 512, 1024, 2048, 8192];

	private byte[] _input = [];
	private byte[] _output = [];
	private readonly List<IStreamCipher> _cryptos = [];

	protected ReadOnlySpan<byte> Input => _input;

	protected Span<byte> Output => _output;

	[GlobalSetup]
	public void Setup()
	{
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_output = new byte[ByteLength];

		SetupCryptos();
	}

	protected abstract void SetupCryptos();

	protected T Register<T>(T crypto) where T : IStreamCipher
	{
		_cryptos.Add(crypto);
		return crypto;
	}

	protected void Run<T>(T crypto) where T : IStreamCipher
	{
		crypto.Xor(_input, _output);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		foreach (IStreamCipher crypto in _cryptos)
		{
			crypto.Dispose();
		}

		_cryptos.Clear();
	}
}
