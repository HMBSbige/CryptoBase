using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.AeadCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using CryptoBase.SymmetricCryptos.BlockCryptos.Aes;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.SymmetricCryptos.AeadCryptos;

[MemoryDiagnoser]
public class AesGcmBenchmark
{
	[Params(0, 16, 256, 1024, 8192)]
	public int ByteLength { get; set; }

	private IAeadCrypto _cryptoBase = null!;
	private IAeadCrypto _bcl = null!;
	private IBlockCipher _bouncyCastlePrimitive = null!;
	private KeyParameter _bouncyCastleKey = null!;
	private byte[] _input = [];
	private byte[] _output = [];
	private byte[] _bouncyCastleOutput = [];
	private byte[] _nonce = [];
	private byte[] _tag = [];
	private byte[] _associatedData = [];

	[GlobalSetup]
	public void Setup()
	{
		byte[] key = RandomNumberGenerator.GetBytes(16);
		_cryptoBase = new GcmMode128<AesCipher>(AesCipher.Create(key));
		_bcl = new DefaultAesGcmCrypto(key);
		_bouncyCastlePrimitive = AesUtilities.CreateEngine();
		_bouncyCastleKey = new KeyParameter(key);
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_output = new byte[ByteLength];
		_bouncyCastleOutput = new byte[checked(ByteLength + 16)];
		_nonce = RandomNumberGenerator.GetBytes(12);
		_tag = new byte[16];
		_associatedData = RandomNumberGenerator.GetBytes(37);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_cryptoBase.Dispose();
		_bcl.Dispose();
	}

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		_cryptoBase.Encrypt(_nonce, _input, _output, _tag, _associatedData);
	}

	[Benchmark]
	public void Bcl()
	{
		_bcl.Encrypt(_nonce, _input, _output, _tag, _associatedData);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		GcmBlockCipher engine = new(_bouncyCastlePrimitive);
		engine.Init(true, new AeadParameters(_bouncyCastleKey, 128, _nonce));
		engine.ProcessAadBytes(_associatedData);
		int written = engine.ProcessBytes(_input, _bouncyCastleOutput);
		engine.DoFinal(_bouncyCastleOutput.AsSpan(written));
	}
}

[MemoryDiagnoser]
public class SM4GcmBenchmark
{
	[Params(0, 16, 256, 1024, 8192)]
	public int ByteLength { get; set; }

	private IAeadCrypto _cryptoBase = null!;
	private KeyParameter _bouncyCastleKey = null!;
	private byte[] _input = [];
	private byte[] _output = [];
	private byte[] _bouncyCastleOutput = [];
	private byte[] _nonce = [];
	private byte[] _tag = [];
	private byte[] _associatedData = [];

	[GlobalSetup]
	public void Setup()
	{
		byte[] key = RandomNumberGenerator.GetBytes(16);
		_cryptoBase = new GcmMode128<SM4Cipher>(SM4Cipher.Create(key));
		_bouncyCastleKey = new KeyParameter(key);
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_output = new byte[ByteLength];
		_bouncyCastleOutput = new byte[checked(ByteLength + 16)];
		_nonce = RandomNumberGenerator.GetBytes(12);
		_tag = new byte[16];
		_associatedData = RandomNumberGenerator.GetBytes(37);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_cryptoBase.Dispose();
	}

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		_cryptoBase.Encrypt(_nonce, _input, _output, _tag, _associatedData);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		GcmBlockCipher engine = new(new SM4Engine());
		engine.Init(true, new AeadParameters(_bouncyCastleKey, 128, _nonce));
		engine.ProcessAadBytes(_associatedData);
		int written = engine.ProcessBytes(_input, _bouncyCastleOutput);
		engine.DoFinal(_bouncyCastleOutput.AsSpan(written));
	}
}
