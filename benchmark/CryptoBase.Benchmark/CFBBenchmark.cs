using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class CFBBenchmark : StreamCryptoBenchmarkBase
{
	private IStreamCrypto _aesCfb = null!;
	private IStreamCrypto _sm4Cfb = null!;

	protected override void SetupCryptos()
	{
		byte[] key = RandomNumberGenerator.GetBytes(16);
		byte[] iv = RandomNumberGenerator.GetBytes(16);

		_aesCfb = Register(StreamCryptoCreate.AesCfb(true, key, iv));
		_sm4Cfb = Register(StreamCryptoCreate.Sm4Cfb(true, key, iv));
	}

	[Benchmark(Baseline = true)]
	public void AesCfb()
	{
		Run(_aesCfb);
	}

	[Benchmark]
	public void Sm4Cfb()
	{
		Run(_sm4Cfb);
	}
}
