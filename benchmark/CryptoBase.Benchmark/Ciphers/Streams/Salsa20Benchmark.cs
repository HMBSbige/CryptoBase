using BenchmarkDotNet.Attributes;
using CryptoBase.Ciphers.Streams;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Ciphers.Streams;

[MemoryDiagnoser]
public class Salsa20Benchmark : StreamCipherBenchmarkBase
{
	private Salsa20Cipher _crypto = null!;
	private Salsa20Engine _bcEngine = null!;

	protected override void SetupCryptos()
	{
		byte[] key = RandomNumberGenerator.GetBytes(32);
		byte[] iv = RandomNumberGenerator.GetBytes(8);

		_crypto = Register(new Salsa20Cipher(key, iv));
		_bcEngine = new Salsa20Engine();
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
