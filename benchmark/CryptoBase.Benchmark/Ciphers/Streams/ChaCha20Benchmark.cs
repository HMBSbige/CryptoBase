using BenchmarkDotNet.Attributes;
using CryptoBase.Ciphers.Streams;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Ciphers.Streams;

[MemoryDiagnoser]
public class ChaCha20Benchmark : StreamCipherBenchmarkBase
{
	private ChaCha20Cipher _crypto = null!;
	private ChaCha7539Engine _bcEngine = null!;

	protected override void SetupCryptos()
	{
		byte[] key = RandomNumberGenerator.GetBytes(32);
		byte[] iv = RandomNumberGenerator.GetBytes(12);

		_crypto = Register(new ChaCha20Cipher(key, iv));
		_bcEngine = new ChaCha7539Engine();
		_bcEngine.Init(false, new ParametersWithIV(new KeyParameter(key), iv));
	}

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		Run(_crypto);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		_bcEngine.ProcessBytes(Input, Output);
	}
}
