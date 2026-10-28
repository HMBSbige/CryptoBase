using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Ciphers.Aead;

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class SM4GcmBenchmark
{
	[Params(0, 16, 112, 128, 256, 512, 768, 1008, 1024, 2032, 8192)]
	public int ByteLength { get; set; }

	private GcmMode<SM4Cipher> _cryptoBase = null!;
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
		_cryptoBase = GcmMode<SM4Cipher>.Create(key);
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
		BouncyCastleDecrypt();
		AeadBenchmarkUtils.ThrowIfNotEqual(_input, _output, "BouncyCastle");
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_cryptoBase.Dispose();
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Encrypt")]
	public void CryptoBase()
	{
		_cryptoBase.Encrypt(_nonce, _input, _output, _tag, _associatedData);
	}

	[Benchmark]
	[BenchmarkCategory("Encrypt")]
	public void BouncyCastle()
	{
		AeadBenchmarkUtils.BouncyCastleEncrypt(new GcmBlockCipher(new SM4Engine()), _bouncyCastleKey, _nonce, _input, _bouncyCastleOutput, _associatedData);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Decrypt")]
	public bool CryptoBaseDecrypt()
	{
		return _cryptoBase.TryDecrypt(_nonce, _ciphertext, _ciphertextTag, _output, _associatedData);
	}

	[Benchmark]
	[BenchmarkCategory("Decrypt")]
	public void BouncyCastleDecrypt()
	{
		AeadBenchmarkUtils.BouncyCastleDecrypt(new GcmBlockCipher(new SM4Engine()), _bouncyCastleKey, _nonce, _bouncyCastleCiphertext, _output, _associatedData);
	}
}
