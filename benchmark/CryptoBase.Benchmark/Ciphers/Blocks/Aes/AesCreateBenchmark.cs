using BenchmarkDotNet.Attributes;
using CryptoBase.Ciphers.Blocks.Aes;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Ciphers.Blocks.Aes;

[MemoryDiagnoser]
public class AesCreateBenchmark
{
	[Params(16, 24, 32)]
	public int KeyLength { get; set; }

	private byte[] _key = [];
	private KeyParameter _bouncyCastleKey = null!;
	private IBlockCipher _bcEncryptionEngine = default!;
	private IBlockCipher _bcDecryptionEngine = default!;

	[GlobalSetup]
	public void Setup()
	{
		_key = RandomNumberGenerator.GetBytes(KeyLength);
		_bouncyCastleKey = new KeyParameter(_key);
		_bcEncryptionEngine = AesUtilities.CreateEngine();
		_bcDecryptionEngine = AesUtilities.CreateEngine();
	}

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		using AesCipher cipher = AesCipher.Create(_key);
	}

	[Benchmark]
	public void CryptoBaseSoftware()
	{
		using AesCipherSoftware cipher = AesCipherSoftware.Create(_key);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		_bcEncryptionEngine.Init(true, _bouncyCastleKey);
		_bcDecryptionEngine.Init(false, _bouncyCastleKey);
	}
}
