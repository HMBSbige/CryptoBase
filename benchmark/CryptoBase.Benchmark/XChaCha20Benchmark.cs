using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class XChaCha20Benchmark : StreamCryptoBenchmarkBase
{
	private IStreamCrypto _crypto = null!;

	protected override void SetupCryptos()
	{
		byte[] key = RandomNumberGenerator.GetBytes(32);
		byte[] iv = RandomNumberGenerator.GetBytes(24);

		_crypto = Register(new XChaCha20Crypto(key, iv));
	}

	[Benchmark]
	public void Default()
	{
		Run(_crypto);
	}
}
