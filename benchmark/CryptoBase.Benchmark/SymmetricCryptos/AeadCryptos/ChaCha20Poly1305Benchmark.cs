using BenchmarkDotNet.Attributes;
using CryptoBase.SymmetricCryptos.AeadCryptos;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using BouncyCastleChaCha20Poly1305 = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;

namespace CryptoBase.Benchmark.SymmetricCryptos.AeadCryptos;

[MemoryDiagnoser]
public class ChaCha20Poly1305Benchmark
{
	[Params(64, 256, 1024, 1025, 8192)]
	public int ByteLength { get; set; }

	private ChaCha20Poly1305Crypto _cryptoBase = null!;
	private DefaultChaCha20Poly1305Crypto _bcl = null!;
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
		_cryptoBase = new ChaCha20Poly1305Crypto(key);
		_bcl = new DefaultChaCha20Poly1305Crypto(key);
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

[MemoryDiagnoser]
public class XChaCha20Poly1305Benchmark
{
	[Params(64, 256, 1024, 1025, 8192)]
	public int ByteLength { get; set; }

	private XChaCha20Poly1305Crypto _cryptoBase = null!;
	private byte[] _input = [];
	private byte[] _output = [];
	private byte[] _nonce = [];
	private byte[] _tag = [];
	private byte[] _associatedData = [];

	[GlobalSetup]
	public void Setup()
	{
		_cryptoBase = new XChaCha20Poly1305Crypto(RandomNumberGenerator.GetBytes(32));
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_output = new byte[ByteLength];
		_nonce = RandomNumberGenerator.GetBytes(24);
		_tag = new byte[16];
		_associatedData = RandomNumberGenerator.GetBytes(29);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_cryptoBase.Dispose();
	}

	[Benchmark]
	public void CryptoBase()
	{
		_cryptoBase.Encrypt(_nonce, _input, _output, _tag, _associatedData);
	}
}
