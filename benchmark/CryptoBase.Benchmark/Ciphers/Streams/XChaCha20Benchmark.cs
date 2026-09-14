using BenchmarkDotNet.Attributes;
using CryptoBase.Ciphers.Streams;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Ciphers.Streams;

[MemoryDiagnoser]
public class XChaCha20Benchmark : StreamCipherBenchmarkBase
{
	private XChaCha20Cipher _crypto = null!;

	protected override void SetupCryptos()
	{
		byte[] key = RandomNumberGenerator.GetBytes(32);
		byte[] iv = RandomNumberGenerator.GetBytes(24);

		_crypto = Register(new XChaCha20Cipher(key, iv));
	}

	[Benchmark]
	public void CryptoBase()
	{
		Run(_crypto);
	}
}
