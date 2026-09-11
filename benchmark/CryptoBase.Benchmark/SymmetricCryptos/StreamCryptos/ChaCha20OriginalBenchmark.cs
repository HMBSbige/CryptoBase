using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.SymmetricCryptos.StreamCryptos;

[MemoryDiagnoser]
public class ChaCha20OriginalBenchmark : StreamCryptoBenchmarkBase
{
	private IStreamCrypto _crypto = null!;
	private ChaChaEngine _bcEngine = null!;

	protected override void SetupCryptos()
	{
		byte[] key = RandomNumberGenerator.GetBytes(32);
		byte[] iv = RandomNumberGenerator.GetBytes(8);

		_crypto = Register(new ChaCha20OriginalCrypto(key, iv));
		_bcEngine = new ChaChaEngine();
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
