using BenchmarkDotNet.Attributes;
using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes.Gcm;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Ciphers.Aead;

[MemoryDiagnoser]
public class SM4GcmBenchmark
{
	[Params(0, 16, 256, 1024, 8192)]
	public int ByteLength { get; set; }

	private GcmMode128<SM4Cipher> _cryptoBase = null!;
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
		_cryptoBase = GcmMode128<SM4Cipher>.Create(key);
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
