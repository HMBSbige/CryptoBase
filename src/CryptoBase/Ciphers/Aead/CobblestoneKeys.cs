using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;

namespace CryptoBase.Ciphers.Aead;

/// <summary>
/// Holds the AES-GCM key and base nonce of one Cobblestone message and transforms its chunks.
/// </summary>
/// <remarks>The owner disposes it exactly once and checks for disposal before each chunk operation.</remarks>
internal struct CobblestoneKeys : IDisposable
{
	private readonly GcmMode<AesCipher> _aead;

	// The base nonce in the first 12 bytes; the chunk index is XOR'd into the big-endian 64-bit suffix in bytes 4 to 11.
	private Vector128<byte> _baseNonce;

	public CobblestoneKeys(ReadOnlySpan<byte> aeadKey, ReadOnlySpan<byte> baseNonce)
	{
		Debug.Assert(baseNonce.Length is Cobblestone.NonceSize);

		_aead = GcmMode<AesCipher>.Create(aeadKey);
		baseNonce.CopyTo(_baseNonce.AsSpan());
	}

	public readonly void EncryptChunk(long index, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
	{
		ValidateIndex(index);
		ArgumentOutOfRangeException.ThrowIfGreaterThan(plaintext.Length, Cobblestone.ChunkSize, nameof(plaintext));
		ArgumentOutOfRangeException.ThrowIfLessThan(ciphertext.Length, plaintext.Length + Cobblestone.TagSize, nameof(ciphertext));
		ciphertext = ciphertext.Slice(0, plaintext.Length + Cobblestone.TagSize);
		CipherBufferGuard.SourceDestinationOverlap(plaintext, ciphertext, nameof(ciphertext));

		Vector128<byte> nonce = GetNonce(index);
		_aead.Encrypt(nonce.AsReadOnlySpan().Slice(0, Cobblestone.NonceSize), plaintext, ciphertext.Slice(0, plaintext.Length), ciphertext.Slice(plaintext.Length));
	}

	public readonly bool TryDecryptChunk(long index, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
	{
		ValidateIndex(index);
		ArgumentOutOfRangeException.ThrowIfLessThan(ciphertext.Length, Cobblestone.TagSize, nameof(ciphertext));
		ArgumentOutOfRangeException.ThrowIfGreaterThan(ciphertext.Length, Cobblestone.EncryptedChunkSize, nameof(ciphertext));
		int length = ciphertext.Length - Cobblestone.TagSize;
		ArgumentOutOfRangeException.ThrowIfLessThan(plaintext.Length, length, nameof(plaintext));
		plaintext = plaintext.Slice(0, length);
		CipherBufferGuard.SourceDestinationOverlap(ciphertext, plaintext, nameof(plaintext));

		Vector128<byte> nonce = GetNonce(index);
		return _aead.TryDecrypt(nonce.AsReadOnlySpan().Slice(0, Cobblestone.NonceSize), ciphertext.Slice(0, length), ciphertext.Slice(length), plaintext);
	}

	public void Dispose()
	{
		_aead.Dispose();
		_baseNonce = default;
	}

	/// <summary>
	/// Gets the XOR of the base nonce and <paramref name="index" /> as a 96-bit big-endian integer in the first 12 bytes.
	/// </summary>
	/// <remarks>A vector written with one store: a stack allocation would add a stack cookie, and narrower stores would stall the wider loads of the nonce in AES-GCM.</remarks>
	private readonly Vector128<byte> GetNonce(long index)
	{
		ulong bigEndianIndex = BinaryPrimitives.ReverseEndianness((ulong)index);
		return _baseNonce ^ Vector128.Create(bigEndianIndex << 32, bigEndianIndex >> 32).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ValidateIndex(long index)
	{
		ArgumentOutOfRangeException.ThrowIfNegative(index);
		ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, Cobblestone.MaxChunkCount);
	}
}
