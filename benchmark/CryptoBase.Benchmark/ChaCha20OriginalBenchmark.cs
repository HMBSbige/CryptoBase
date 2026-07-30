using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class ChaCha20OriginalBenchmark : StreamCryptoBenchmarkBase
{
	private IStreamCrypto _crypto = null!;
	private IStreamCrypto _bcCrypto = null!;

	protected override void SetupCryptos()
	{
		byte[] key = RandomNumberGenerator.GetBytes(32);
		byte[] iv = RandomNumberGenerator.GetBytes(8);

		_crypto = Register(new ChaCha20OriginalCrypto(key, iv));
		_bcCrypto = Register(new BcChaCha20OriginalCrypto(key, iv));
	}

	[Benchmark(Baseline = true)]
	public void Default()
	{
		Run(_crypto);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		Run(_bcCrypto);
	}
}
