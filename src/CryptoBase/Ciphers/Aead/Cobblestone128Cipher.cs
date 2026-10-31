namespace CryptoBase.Ciphers.Aead;

/// <summary>
/// Provides Cobblestone-128, the c2sp.org/chunked-encryption instantiation over AES-128-GCM.
/// </summary>
/// <remarks>
/// <para>
/// The context is not stored in the message, so decryption needs the same context.
/// </para>
/// <para>
/// <see cref="Encrypt" /> and <see cref="TryDecrypt" /> handle a whole message in memory. For streams and files, the CryptoBase.IO package builds on <see cref="CreateEncryptor" />, <see cref="CreateDecryptor" /> and the chunk methods of an instance, which holds the keys of one message.
/// </para>
/// </remarks>
public sealed class Cobblestone128Cipher : ICobblestoneCipher<Cobblestone128Cipher>
{
	// Not readonly: a readonly field would make Dispose run on a defensive copy.
	private CobblestoneKeys _keys;
	private bool _disposed;

	private Cobblestone128Cipher(CobblestoneKeys keys)
	{
		_keys = keys;
	}

	/// <inheritdoc />
	/// <remarks>The input key is 16 bytes long.</remarks>
	public static int KeySize => 16;

	/// <inheritdoc />
	/// <remarks>The header is 56 bytes long: the salt and then the commitment.</remarks>
	public static int HeaderSize => Cobblestone.HeaderSize;

	/// <inheritdoc />
	/// <remarks>Full chunks hold 16 KiB.</remarks>
	public static int ChunkSize => Cobblestone.ChunkSize;

	/// <inheritdoc />
	/// <remarks>The tag is 16 bytes long.</remarks>
	public static int TagSize => Cobblestone.TagSize;

	/// <inheritdoc />
	/// <remarks>A message has at most 2^38 chunks, so it is at most 4 PiB - 1 byte long.</remarks>
	public static long MaxChunkCount => Cobblestone.MaxChunkCount;

	static ReadOnlySpan<byte> ICobblestoneCipher<Cobblestone128Cipher>.InfoPrefix => "c2sp.org/chunked-encryption@v1+AEAD_AES_128_GCM\0"u8;

	static Cobblestone128Cipher ICobblestoneCipher<Cobblestone128Cipher>.Create(CobblestoneKeys keys)
	{
		return new Cobblestone128Cipher(keys);
	}

	/// <inheritdoc />
	/// <remarks>The header starts with a new random salt.</remarks>
	public static Cobblestone128Cipher CreateEncryptor(ReadOnlySpan<byte> key, ReadOnlySpan<byte> context, Span<byte> header)
	{
		return Cobblestone<Cobblestone128Cipher>.CreateEncryptor(key, context, header);
	}

	/// <inheritdoc />
	public static Cobblestone128Cipher CreateDecryptor(ReadOnlySpan<byte> key, ReadOnlySpan<byte> context, ReadOnlySpan<byte> header)
	{
		return Cobblestone<Cobblestone128Cipher>.CreateDecryptor(key, context, header);
	}

	/// <summary>
	/// Gets the length of an encrypted message.
	/// </summary>
	/// <param name="plaintextLength">The message length, in bytes.</param>
	/// <returns>The length of the encrypted message, in bytes.</returns>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="plaintextLength" /> is negative or longer than the largest message.</exception>
	public static long GetCiphertextLength(long plaintextLength)
	{
		return Cobblestone.GetCiphertextLength(plaintextLength);
	}

	/// <summary>
	/// Gets the message length of an encrypted message, or fails when no message encrypts to <paramref name="ciphertextLength" /> bytes.
	/// </summary>
	/// <remarks>A length that ends on a chunk boundary belongs to a truncated message, because the last chunk is always shorter than a full one.</remarks>
	/// <param name="ciphertextLength">The length of the encrypted message, in bytes.</param>
	/// <param name="plaintextLength">The message length, in bytes, or zero on failure.</param>
	/// <returns><see langword="true" /> if a message encrypts to <paramref name="ciphertextLength" /> bytes; otherwise, <see langword="false" />.</returns>
	public static bool TryGetPlaintextLength(long ciphertextLength, out long plaintextLength)
	{
		return Cobblestone.TryGetPlaintextLength(ciphertextLength, out plaintextLength);
	}

	/// <summary>
	/// Encrypts a whole message with a new random salt.
	/// </summary>
	/// <param name="key">The 16-byte input key.</param>
	/// <param name="plaintext">The message.</param>
	/// <param name="ciphertext">The buffer that receives the encrypted message in its first <see cref="GetCiphertextLength" /> bytes; it must not overlap <paramref name="plaintext" />.</param>
	/// <param name="context">The context that the message is bound to. It may be empty.</param>
	/// <exception cref="ArgumentException"><paramref name="key" /> has the wrong length, <paramref name="ciphertext" /> is too short, or the buffers overlap.</exception>
	public static void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, ReadOnlySpan<byte> context = default)
	{
		Cobblestone<Cobblestone128Cipher>.Encrypt(key, plaintext, ciphertext, context);
	}

	/// <summary>
	/// Authenticates a whole encrypted message and decrypts it.
	/// </summary>
	/// <param name="key">The 16-byte input key.</param>
	/// <param name="ciphertext">The encrypted message.</param>
	/// <param name="plaintext">The buffer that receives the message in its first bytes, as many as <see cref="TryGetPlaintextLength" /> gives; it must not overlap <paramref name="ciphertext" />.</param>
	/// <param name="context">The context that the message was encrypted with.</param>
	/// <returns>
	/// <see langword="false" /> if the message fails authentication because it was truncated, extended or modified, or encrypted with a different key or context; if <paramref name="ciphertext" /> has a valid length, the output prefix of the message length is then cleared. <see langword="true" /> on success.
	/// </returns>
	/// <exception cref="ArgumentException"><paramref name="key" /> has the wrong length, or <paramref name="ciphertext" /> has a valid length and <paramref name="plaintext" /> is too short or overlaps it.</exception>
	public static bool TryDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, ReadOnlySpan<byte> context = default)
	{
		return Cobblestone<Cobblestone128Cipher>.TryDecrypt(key, ciphertext, plaintext, context);
	}

	/// <inheritdoc />
	public void EncryptChunk(long index, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_keys.EncryptChunk(index, plaintext, ciphertext);
	}

	/// <inheritdoc />
	public bool TryDecryptChunk(long index, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _keys.TryDecryptChunk(index, ciphertext, plaintext);
	}

	/// <inheritdoc />
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_disposed = true;
		_keys.Dispose();
	}
}
