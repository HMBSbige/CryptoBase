using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Ciphers.Aead;

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class AesGcmBenchmark
{
	[Params(0, 16, 256, 1024, 8192)]
	public int ByteLength { get; set; }

	private GcmMode<AesCipher> _cryptoBase = null!;
	private AesGcm _bcl = null!;
	private IBlockCipher _bouncyCastlePrimitive = null!;
	private KeyParameter _bouncyCastleKey = null!;
	private byte[] _input = [];
	private byte[] _output = [];
	private byte[] _bouncyCastleOutput = [];
	private byte[] _nonce = [];
	private byte[] _tag = [];
	private byte[] _associatedData = [];
	private byte[] _ciphertext = [];
	private byte[] _ciphertextTag = [];
	private byte[] _bouncyCastleCiphertext = [];

	[GlobalSetup]
	public void Setup()
	{
		byte[] key = RandomNumberGenerator.GetBytes(16);
		_cryptoBase = GcmMode<AesCipher>.Create(key);
		_bcl = new AesGcm(key, 16);
		_bouncyCastlePrimitive = AesUtilities.CreateEngine();
		_bouncyCastleKey = new KeyParameter(key);
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_output = new byte[ByteLength];
		_bouncyCastleOutput = new byte[checked(ByteLength + 16)];
		_nonce = RandomNumberGenerator.GetBytes(12);
		_tag = new byte[16];
		_associatedData = RandomNumberGenerator.GetBytes(37);
		_ciphertext = new byte[ByteLength];
		_ciphertextTag = new byte[16];
		_cryptoBase.Encrypt(_nonce, _input, _ciphertext, _ciphertextTag, _associatedData);
		_bouncyCastleCiphertext = [.. _ciphertext, .. _ciphertextTag];

		if (!CryptoBaseDecrypt())
		{
			throw new InvalidOperationException("CryptoBase rejected the ciphertext.");
		}

		AeadBenchmarkUtils.ThrowIfNotEqual(_input, _output, "CryptoBase");
		BclDecrypt();
		AeadBenchmarkUtils.ThrowIfNotEqual(_input, _output, "BCL");
		BouncyCastleDecrypt();
		AeadBenchmarkUtils.ThrowIfNotEqual(_input, _output, "BouncyCastle");
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_cryptoBase.Dispose();
		_bcl.Dispose();
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Encrypt")]
	public void CryptoBase()
	{
		_cryptoBase.Encrypt(_nonce, _input, _output, _tag, _associatedData);
	}

	[Benchmark]
	[BenchmarkCategory("Encrypt")]
	public void Bcl()
	{
		_bcl.Encrypt(_nonce, _input, _output, _tag, _associatedData);
	}

	[Benchmark]
	[BenchmarkCategory("Encrypt")]
	public void BouncyCastle()
	{
		AeadBenchmarkUtils.BouncyCastleEncrypt(new GcmBlockCipher(_bouncyCastlePrimitive), _bouncyCastleKey, _nonce, _input, _bouncyCastleOutput, _associatedData);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Decrypt")]
	public bool CryptoBaseDecrypt()
	{
		return _cryptoBase.TryDecrypt(_nonce, _ciphertext, _ciphertextTag, _output, _associatedData);
	}

	[Benchmark]
	[BenchmarkCategory("Decrypt")]
	public void BclDecrypt()
	{
		_bcl.Decrypt(_nonce, _ciphertext, _ciphertextTag, _output, _associatedData);
	}

	[Benchmark]
	[BenchmarkCategory("Decrypt")]
	public void BouncyCastleDecrypt()
	{
		AeadBenchmarkUtils.BouncyCastleDecrypt(new GcmBlockCipher(_bouncyCastlePrimitive), _bouncyCastleKey, _nonce, _bouncyCastleCiphertext, _output, _associatedData);
	}
}
