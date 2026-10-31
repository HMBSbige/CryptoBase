namespace CryptoBase.Ciphers.Aead;

/// <summary>
/// Holds the layout of c2sp.org/chunked-encryption messages over AES-GCM, which Cobblestone-128 and Cobblestone-256 share.
/// </summary>
/// <remarks>
/// A message is the salt, the commitment and then the chunks.
/// </remarks>
internal static class Cobblestone
{
	public const int SaltSize = 24;
	public const int CommitmentSize = 32;
	public const int HeaderSize = SaltSize + CommitmentSize;
	public const int NonceSize = 12;
	public const int TagSize = 16;
	public const int ChunkSize = 16 * 1024;
	public const int EncryptedChunkSize = ChunkSize + TagSize;
	public const long MaxChunkCount = 1L << 38;
	public const long MaxMessageLength = MaxChunkCount * ChunkSize - 1;

	public static long GetCiphertextLength(long plaintextLength, [CallerArgumentExpression(nameof(plaintextLength))] string? paramName = null)
	{
		ArgumentOutOfRangeException.ThrowIfNegative(plaintextLength, paramName);
		ArgumentOutOfRangeException.ThrowIfGreaterThan(plaintextLength, MaxMessageLength, paramName);

		return HeaderSize + plaintextLength + (plaintextLength / ChunkSize + 1) * TagSize;
	}

	public static bool TryGetPlaintextLength(long ciphertextLength, out long plaintextLength)
	{
		long fullChunks = Math.DivRem(ciphertextLength - HeaderSize, EncryptedChunkSize, out long last);

		// The last chunk holds at least a tag and less than a full chunk, so a length on a chunk boundary is truncated.
		if (ciphertextLength < HeaderSize || last < TagSize || fullChunks >= MaxChunkCount)
		{
			plaintextLength = 0;
			return false;
		}

		plaintextLength = fullChunks * ChunkSize + last - TagSize;
		return true;
	}

	/// <summary>
	/// Encrypts <paramref name="plaintext" /> into the chunks that start <paramref name="ciphertext" />, which must be long enough.
	/// </summary>
	public static void EncryptChunks(in CobblestoneKeys keys, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
	{
		long index = 0;

		while (plaintext.Length >= ChunkSize)
		{
			keys.EncryptChunk(index++, plaintext.Slice(0, ChunkSize), ciphertext);
			plaintext = plaintext.Slice(ChunkSize);
			ciphertext = ciphertext.Slice(EncryptedChunkSize);
		}

		keys.EncryptChunk(index, plaintext, ciphertext);
	}

	/// <summary>
	/// Decrypts the chunks in <paramref name="ciphertext" />, whose length must be valid, into <paramref name="plaintext" />, and fails at the first chunk that fails authentication.
	/// </summary>
	public static bool TryDecryptChunks(in CobblestoneKeys keys, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
	{
		long index = 0;

		// A valid length leaves a last chunk shorter than a full one.
		while (ciphertext.Length >= EncryptedChunkSize)
		{
			if (!keys.TryDecryptChunk(index++, ciphertext.Slice(0, EncryptedChunkSize), plaintext))
			{
				return false;
			}

			ciphertext = ciphertext.Slice(EncryptedChunkSize);
			plaintext = plaintext.Slice(ChunkSize);
		}

		return keys.TryDecryptChunk(index, ciphertext, plaintext);
	}
}
