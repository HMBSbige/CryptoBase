using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.AEADCryptos;
using CryptoBase.SymmetricCryptos.AEADCryptos;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class ChaCha20Poly1305Benchmark
{
	[Params(1024, 8192, 16384)]
	public int ByteLength { get; set; }

	private IAEADCrypto _managed = null!;
	private IAEADCrypto? _dotNet;
	private IAEADCrypto _bc = null!;
	private IAEADCrypto _xChaCha20Managed = null!;

	private byte[] _input = [];
	private byte[] _output = [];
	private byte[] _nonce12 = [];
	private byte[] _nonce24 = [];
	private byte[] _tag = [];

	[GlobalSetup]
	public void Setup()
	{
		byte[] key = RandomNumberGenerator.GetBytes(32);

		_managed = new ChaCha20Poly1305Crypto(key);
		_dotNet = DefaultChaCha20Poly1305Crypto.IsSupported ? new DefaultChaCha20Poly1305Crypto(key) : default;
		_bc = new BcChaCha20Poly1305Crypto(key);
		_xChaCha20Managed = new XChaCha20Poly1305Crypto(key);

		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_output = new byte[ByteLength];
		_nonce12 = RandomNumberGenerator.GetBytes(12);
		_nonce24 = RandomNumberGenerator.GetBytes(24);
		_tag = new byte[16];
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_managed.Dispose();
		_dotNet?.Dispose();
		_bc.Dispose();
		_xChaCha20Managed.Dispose();
	}

	private void Encrypt(IAEADCrypto crypto, byte[] nonce)
	{
		crypto.Encrypt(nonce, _input, _output, _tag);
	}

	[Benchmark(Baseline = true)]
	public void Managed()
	{
		Encrypt(_managed, _nonce12);
	}

	[Benchmark]
	public void DotNet()
	{
		Encrypt(_dotNet ?? throw new NotSupportedException(), _nonce12);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		Encrypt(_bc, _nonce12);
	}

	[Benchmark]
	public void XChaCha20Managed()
	{
		Encrypt(_xChaCha20Managed, _nonce24);
	}
}
