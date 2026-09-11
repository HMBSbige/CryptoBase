using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.SymmetricCryptos.StreamCryptos;

public abstract class StreamCryptoBenchmarkBase
{
	[ParamsSource(nameof(ByteLengths))]
	public int ByteLength { get; set; }

	public virtual IEnumerable<int> ByteLengths => [63, 64, 65, 256, 512, 1024, 2048, 8192];

	private byte[] _input = [];
	private byte[] _output = [];
	private readonly List<IStreamCrypto> _cryptos = [];

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

	protected IStreamCrypto Register(IStreamCrypto crypto)
	{
		_cryptos.Add(crypto);
		return crypto;
	}

	protected void Run(IStreamCrypto crypto)
	{
		crypto.Update(_input, _output);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		foreach (IStreamCrypto crypto in _cryptos)
		{
			crypto.Dispose();
		}

		_cryptos.Clear();
	}
}
