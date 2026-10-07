using BenchmarkDotNet.Attributes;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Ciphers.Aead;

[MemoryDiagnoser]
public class AesCcmBenchmark
{
	[Params(0, 16, 17, 256, 1024, 8192)]
	public int ByteLength { get; set; }

	[Params(16, 24, 32)]
	public int KeyLength { get; set; }

	private CcmMode128<AesCipher> _cryptoBase = null!;
	private Ccm8Mode128<AesCipher> _cryptoBase8 = null!;
	private AesCcm? _bcl;
	private IBlockCipher _bouncyCastlePrimitive = null!;
	private KeyParameter _bouncyCastleKey = null!;
	private byte[] _input = [];
	private byte[] _ciphertext = [];
	private byte[] _output = [];
	private byte[] _bouncyCastleOutput = [];
	private byte[] _nonce = [];
	private byte[] _tag = [];
	private byte[] _tag8 = [];
	private byte[] _associatedData = [];

	[GlobalSetup]
	public void Setup()
	{
		byte[] key = RandomNumberGenerator.GetBytes(KeyLength);
		_cryptoBase = CcmMode128<AesCipher>.Create(key);
		_cryptoBase8 = Ccm8Mode128<AesCipher>.Create(key);
		_bcl = AesCcm.IsSupported ? new AesCcm(key) : null;
		_bouncyCastlePrimitive = AesUtilities.CreateEngine();
		_bouncyCastleKey = new KeyParameter(key);
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_ciphertext = new byte[ByteLength];
		_output = new byte[ByteLength];
		_bouncyCastleOutput = new byte[checked(ByteLength + 16)];
		_nonce = RandomNumberGenerator.GetBytes(12);
		_tag = new byte[16];
		_tag8 = new byte[8];
		_associatedData = RandomNumberGenerator.GetBytes(37);
		_cryptoBase.Encrypt(_nonce, _input, _ciphertext, _tag, _associatedData);
		_cryptoBase8.Encrypt(_nonce, _input, _ciphertext, _tag8, _associatedData);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_cryptoBase.Dispose();
		_cryptoBase8.Dispose();
		_bcl?.Dispose();
	}

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		_cryptoBase.Encrypt(_nonce, _input, _output, _tag, _associatedData);
	}

	[Benchmark]
	public void CryptoBaseCcm8()
	{
		_cryptoBase8.Encrypt(_nonce, _input, _output, _tag8, _associatedData);
	}

	[Benchmark]
	public bool CryptoBaseDecrypt()
	{
		return _cryptoBase.TryDecrypt(_nonce, _ciphertext, _tag, _output, _associatedData);
	}

	[Benchmark]
	public bool CryptoBaseCcm8Decrypt()
	{
		return _cryptoBase8.TryDecrypt(_nonce, _ciphertext, _tag8, _output, _associatedData);
	}

	[Benchmark]
	public void Bcl()
	{
		(_bcl ?? throw new PlatformNotSupportedException()).Encrypt(_nonce, _input, _output, _tag, _associatedData);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		CcmBlockCipher engine = new(_bouncyCastlePrimitive);
		engine.Init(true, new AeadParameters(_bouncyCastleKey, 128, _nonce));
		engine.ProcessAadBytes(_associatedData);
		int written = engine.ProcessBytes(_input, _bouncyCastleOutput);
		engine.DoFinal(_bouncyCastleOutput.AsSpan(written));
	}
}
