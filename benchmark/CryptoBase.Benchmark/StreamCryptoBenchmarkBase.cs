using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

/// <summary>
/// 流加密稳态吞吐基准基类：实例在 GlobalSetup 创建并复用，测量区域内只有 Update
/// </summary>
public abstract class StreamCryptoBenchmarkBase
{
	[Params(1024, 8192)]
	public int ByteLength { get; set; }

	private byte[] _input = [];
	private byte[] _output = [];
	private readonly List<IStreamCrypto> _cryptos = [];

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
