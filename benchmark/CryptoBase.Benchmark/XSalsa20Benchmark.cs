using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class XSalsa20Benchmark : StreamCryptoBenchmarkBase
{
	private IStreamCrypto _crypto = null!;
	private IStreamCrypto _bcCrypto = null!;

	protected override void SetupCryptos()
	{
		byte[] key = RandomNumberGenerator.GetBytes(32);
		byte[] iv = RandomNumberGenerator.GetBytes(24);

		_crypto = Register(new XSalsa20Crypto(key, iv));
		_bcCrypto = Register(new BcXSalsa20Crypto(key, iv));
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
