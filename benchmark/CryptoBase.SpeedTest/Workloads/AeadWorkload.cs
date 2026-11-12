namespace CryptoBase.SpeedTest.Workloads;

internal sealed class AeadWorkload<T> : Workload where T : IAeadCipher<T>
{
	private readonly T _cipher;
	private readonly bool _decrypt;
	private readonly byte[] _nonce = TestData.Sequence(T.NonceSize);
	private readonly byte[] _plaintext;
	private readonly byte[] _ciphertext;
	private readonly byte[] _tag = new byte[T.TagSize];
	private readonly byte[] _output;
	private readonly byte[] _outputTag = new byte[T.TagSize];

	public AeadWorkload(int inputSize, int keySize, bool decrypt)
	{
		_cipher = T.Create(TestData.Sequence(keySize));
		_decrypt = decrypt;
		_plaintext = TestData.Random(inputSize);
		_ciphertext = new byte[inputSize];
		_output = new byte[inputSize];
		_cipher.Encrypt(_nonce, _plaintext, _ciphertext, _tag);
	}

	public override void Verify()
	{
		SelfTestException.ThrowIfFalse(_cipher.TryDecrypt(_nonce, _ciphertext, _tag, _output), "Decryption rejected the tag of a message just encrypted.");
		SelfTestException.ThrowIfNotEqual(_plaintext, _output, "Decryption did not restore the plaintext.");

		_tag[0] ^= 1;
		bool forged = _cipher.TryDecrypt(_nonce, _ciphertext, _tag, _output);
		_tag[0] ^= 1;
		SelfTestException.ThrowIfFalse(!forged, "Decryption accepted a modified tag.");
	}

	public override void Run(long iterations)
	{
		if (_decrypt)
		{
			Decrypt(_cipher, _nonce, _ciphertext, _tag, _output, iterations);
		}
		else
		{
			Encrypt(_cipher, _nonce, _plaintext, _output, _outputTag, iterations);
		}
	}

	private static void Encrypt<TCipher>(TCipher cipher, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> output, Span<byte> tag, long iterations) where TCipher : IAeadCipher<TCipher>
	{
		for (long i = 0; i < iterations; ++i)
		{
			cipher.Encrypt(nonce, plaintext, output, tag);
		}
	}

	private static void Decrypt<TCipher>(TCipher cipher, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> output, long iterations) where TCipher : IAeadCipher<TCipher>
	{
		for (long i = 0; i < iterations; ++i)
		{
			if (!cipher.TryDecrypt(nonce, ciphertext, tag, output))
			{
				SelfTestException.Throw("Decryption rejected a valid tag.");
			}
		}
	}

	public override void Dispose()
	{
		_cipher.Dispose();
	}
}
