using BenchmarkDotNet.Attributes;
using CryptoBase.Ciphers.Aead;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using BouncyCastleChaCha20Poly1305 = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;

namespace CryptoBase.Benchmark.Ciphers.Aead;

[MemoryDiagnoser]
public class ChaCha20Poly1305Benchmark
{
	[Params(64, 256, 1024, 1025, 8192)]
	public int ByteLength { get; set; }

	private ChaCha20Poly1305Cipher _cryptoBase = null!;
	private ChaCha20Poly1305 _bcl = null!;
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
		byte[] key = RandomNumberGenerator.GetBytes(32);
		_cryptoBase = new ChaCha20Poly1305Cipher(key);
		_bcl = new ChaCha20Poly1305(key);
		_bouncyCastleKey = new KeyParameter(key);
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_output = new byte[ByteLength];
		_bouncyCastleOutput = new byte[checked(ByteLength + 16)];
		_nonce = RandomNumberGenerator.GetBytes(12);
		_tag = new byte[16];
		_associatedData = RandomNumberGenerator.GetBytes(29);
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
		BouncyCastleChaCha20Poly1305 engine = new();
		engine.Init(true, new AeadParameters(_bouncyCastleKey, 128, _nonce));
		engine.ProcessAadBytes(_associatedData);
		int written = engine.ProcessBytes(_input, _bouncyCastleOutput);
		engine.DoFinal(_bouncyCastleOutput.AsSpan(written));
	}
}
