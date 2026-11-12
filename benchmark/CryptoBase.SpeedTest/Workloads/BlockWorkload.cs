namespace CryptoBase.SpeedTest.Workloads;

internal sealed class BlockWorkload<T> : Workload where T : IBlockCipher<T>
{
	private readonly T _cipher;
	private readonly bool _decrypt;
	private readonly byte[] _plaintext;
	private readonly byte[] _ciphertext;
	private readonly byte[] _output;

	public BlockWorkload(int inputSize, int keySize, bool decrypt)
	{
		_cipher = T.Create(TestData.Sequence(keySize));
		_decrypt = decrypt;
		_plaintext = TestData.Random(inputSize);
		_ciphertext = new byte[inputSize];
		_output = new byte[inputSize];
		_cipher.EncryptBlocks(_plaintext, _ciphertext);
	}

	public override void Verify()
	{
		_cipher.DecryptBlocks(_ciphertext, _output);
		SelfTestException.ThrowIfNotEqual(_plaintext, _output, "Decryption did not restore the plaintext.");
		SelfTestException.ThrowIfFalse(!_plaintext.AsSpan().SequenceEqual(_ciphertext), "Encryption left the plaintext unchanged.");
	}

	public override void Run(long iterations)
	{
		T cipher = _cipher;
		Span<byte> output = _output;

		if (_decrypt)
		{
			ReadOnlySpan<byte> ciphertext = _ciphertext;

			for (long i = 0; i < iterations; ++i)
			{
				cipher.DecryptBlocks(ciphertext, output);
			}
		}
		else
		{
			ReadOnlySpan<byte> plaintext = _plaintext;

			for (long i = 0; i < iterations; ++i)
			{
				cipher.EncryptBlocks(plaintext, output);
			}
		}
	}

	public override void Dispose()
	{
		_cipher.Dispose();
	}
}
