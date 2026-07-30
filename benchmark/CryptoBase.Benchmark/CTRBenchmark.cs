using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
using CryptoBase.SymmetricCryptos.StreamCryptos;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class CTRBenchmark : StreamCryptoBenchmarkBase
{
	private IStreamCrypto _aesCtr = null!;
	private IStreamCrypto _aesCtr32 = null!;
	private IStreamCrypto _sm4Ctr = null!;

	protected override void SetupCryptos()
	{
		byte[] key = RandomNumberGenerator.GetBytes(16);
		byte[] iv = RandomNumberGenerator.GetBytes(16);

		_aesCtr = Register(StreamCryptoCreate.AesCtr(key, iv));
		_aesCtr32 = Register(new CtrMode128Ctr32<AesCipher>(AesCipher.Create(key), iv));
		_sm4Ctr = Register(StreamCryptoCreate.Sm4Ctr(key, iv));
	}

	[Benchmark(Baseline = true)]
	public void AesCtr()
	{
		Run(_aesCtr);
	}

	[Benchmark]
	public void AesCtr32()
	{
		Run(_aesCtr32);
	}

	[Benchmark]
	public void Sm4Ctr()
	{
		Run(_sm4Ctr);
	}
}
