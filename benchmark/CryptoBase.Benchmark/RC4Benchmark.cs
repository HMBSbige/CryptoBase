using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class RC4Benchmark : StreamCryptoBenchmarkBase
{
	private IStreamCrypto _crypto = null!;
	private IStreamCrypto _bcCrypto = null!;

	protected override void SetupCryptos()
	{
		byte[] key = RandomNumberGenerator.GetBytes(16);

		_crypto = Register(new RC4Crypto(key));
		_bcCrypto = Register(new BcRC4Crypto(key));
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
