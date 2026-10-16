using BenchmarkDotNet.Attributes;
using CryptoBase.Ciphers.Aead;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Ciphers.Aead;

[MemoryDiagnoser]
public class ChaCha20Poly1305DecryptBenchmark
{
	[Params(64, 256, 1024, 1025, 1500, 8192, 65536)]
	public int ByteLength { get; set; }

	[Params(false, true)]
	public bool ExtendedNonce { get; set; }

	private readonly ChaCha20Poly1305Cipher _chacha = new(new byte[32]);
	private readonly XChaCha20Poly1305Cipher _xchacha = new(new byte[32]);
	private byte[] _ciphertext = [];
	private byte[] _plaintext = [];
	private byte[] _nonce = [];
	private readonly byte[] _tag = new byte[16];
	private readonly byte[] _associatedData = new byte[29];

	[GlobalSetup]
	public void Setup()
	{
		_plaintext = RandomNumberGenerator.GetBytes(ByteLength);
		_ciphertext = new byte[ByteLength];
		_nonce = RandomNumberGenerator.GetBytes(ExtendedNonce ? 24 : 12);

		if (ExtendedNonce)
		{
			_xchacha.Encrypt(_nonce, _plaintext, _ciphertext, _tag, _associatedData);
		}
		else
		{
			_chacha.Encrypt(_nonce, _plaintext, _ciphertext, _tag, _associatedData);
		}

		if (!Decrypt())
		{
			throw new InvalidOperationException("The benchmark must measure successful authentication.");
		}
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_chacha.Dispose();
		_xchacha.Dispose();
	}

	[Benchmark]
	public bool Decrypt()
	{
		return ExtendedNonce
			? _xchacha.TryDecrypt(_nonce, _ciphertext, _tag, _plaintext, _associatedData)
			: _chacha.TryDecrypt(_nonce, _ciphertext, _tag, _plaintext, _associatedData);
	}
}
