using BenchmarkDotNet.Attributes;
using CryptoBase.Ciphers.Aead;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Ciphers.Aead;

[MemoryDiagnoser]
public class XChaCha20Poly1305Benchmark
{
	[Params(64, 256, 1024, 1025, 8192)]
	public int ByteLength { get; set; }

	private XChaCha20Poly1305Cipher _cryptoBase = null!;
	private byte[] _input = [];
	private byte[] _output = [];
	private byte[] _nonce = [];
	private byte[] _tag = [];
	private byte[] _associatedData = [];

	[GlobalSetup]
	public void Setup()
	{
		_cryptoBase = new XChaCha20Poly1305Cipher(RandomNumberGenerator.GetBytes(32));
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
