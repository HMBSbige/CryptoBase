namespace CryptoBase.SpeedTest.Workloads;

/// <summary>
/// Encrypts, or authenticates and decrypts, a whole message of a fixed size with the one-shot methods of a chunked cipher.
/// </summary>
/// <remarks>
/// Every iteration is one message: the key derivation from a new random salt, the header and all the chunks.
/// The one-shot methods also pick the implementation that the library prefers for the message length.
/// </remarks>
internal sealed class ChunkedMessageWorkload<T> : Workload where T : IChunkedCipher<T>
{
	private readonly MessageEncryptor _encrypt;
	private readonly MessageDecryptor _tryDecrypt;
	private readonly bool _decrypt;
	private readonly byte[] _key = TestData.Sequence(T.KeySize);
	private readonly byte[] _plaintext;
	private readonly byte[] _ciphertext;
	private readonly byte[] _output;

	public ChunkedMessageWorkload(int inputSize, MessageEncryptor encrypt, MessageDecryptor tryDecrypt, bool decrypt)
	{
		_encrypt = encrypt;
		_tryDecrypt = tryDecrypt;
		_decrypt = decrypt;
		_plaintext = TestData.Random(inputSize);
		_ciphertext = new byte[GetCiphertextLength(inputSize)];
		_output = new byte[_decrypt ? inputSize : _ciphertext.Length];
		encrypt(_key, _plaintext, _ciphertext, default);
	}

	public override void Verify()
	{
		byte[] plaintext = new byte[_plaintext.Length];
		SelfTestException.ThrowIfFalse(_tryDecrypt(_key, _ciphertext, plaintext, default), "Decryption rejected a message just encrypted.");
		SelfTestException.ThrowIfNotEqual(_plaintext, plaintext, "Decryption did not restore the plaintext.");

		plaintext.AsSpan().Clear();
		DecryptChunks(plaintext);
		SelfTestException.ThrowIfNotEqual(_plaintext, plaintext, "Chunk-by-chunk decryption did not restore the plaintext.");

		_ciphertext[^1] ^= 1;
		bool forged = _tryDecrypt(_key, _ciphertext, plaintext, default);
		_ciphertext[^1] ^= 1;
		SelfTestException.ThrowIfFalse(!forged, "Decryption accepted a modified message.");
	}

	public override void Run(long iterations)
	{
		ReadOnlySpan<byte> key = _key;
		Span<byte> output = _output;

		if (_decrypt)
		{
			MessageDecryptor tryDecrypt = _tryDecrypt;
			ReadOnlySpan<byte> ciphertext = _ciphertext;

			for (long i = 0; i < iterations; ++i)
			{
				if (!tryDecrypt(key, ciphertext, output, default))
				{
					SelfTestException.Throw("Decryption rejected a valid message.");
				}
			}
		}
		else
		{
			MessageEncryptor encrypt = _encrypt;
			ReadOnlySpan<byte> plaintext = _plaintext;

			for (long i = 0; i < iterations; ++i)
			{
				encrypt(key, plaintext, output, default);
			}
		}
	}

	private static int GetCiphertextLength(int plaintextLength)
	{
		return checked(T.HeaderSize + plaintextLength + (plaintextLength / T.ChunkSize + 1) * T.TagSize);
	}

	/// <summary>
	/// Decrypts the message through the <see cref="IChunkedCipher{TSelf}" /> interface, following its chunking rules.
	/// </summary>
	private void DecryptChunks(Span<byte> plaintext)
	{
		ReadOnlySpan<byte> ciphertext = _ciphertext;
		using T decryptor = T.CreateDecryptor(_key, default, ciphertext.Slice(0, T.HeaderSize));
		ciphertext = ciphertext.Slice(T.HeaderSize);

		for (long index = 0; ; ++index)
		{
			int length = Math.Min(ciphertext.Length, T.ChunkSize + T.TagSize);
			bool last = length < T.ChunkSize + T.TagSize;
			SelfTestException.ThrowIfFalse(decryptor.TryDecryptChunk(index, ciphertext.Slice(0, length), plaintext), "Decryption rejected a chunk.");

			if (last)
			{
				return;
			}

			ciphertext = ciphertext.Slice(length);
			plaintext = plaintext.Slice(length - T.TagSize);
		}
	}
}

internal delegate void MessageEncryptor(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, ReadOnlySpan<byte> context);

internal delegate bool MessageDecryptor(ReadOnlySpan<byte> key, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, ReadOnlySpan<byte> context);
