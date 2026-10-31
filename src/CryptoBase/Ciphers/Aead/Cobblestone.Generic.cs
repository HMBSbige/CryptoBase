using CryptoBase.Hashes.Sha2;
using CryptoBase.Kdf;
using static CryptoBase.Ciphers.Aead.Cobblestone;

namespace CryptoBase.Ciphers.Aead;

/// <summary>
/// Implements c2sp.org/chunked-encryption over AES-GCM with HKDF-SHA-512 for the instantiation <typeparamref name="TCipher" />.
/// </summary>
internal static class Cobblestone<TCipher> where TCipher : class, ICobblestoneCipher<TCipher>
{
	private const string CommitmentMismatchMessage = "The key or context does not match the ciphertext, or its header was modified.";

	// The HKDF-Expand output for the largest key, a 32-byte AES-256 key.
	private const int MaxOkmLength = 32 + NonceSize + CommitmentSize;

	public static TCipher CreateEncryptor(ReadOnlySpan<byte> key, ReadOnlySpan<byte> context, Span<byte> header)
	{
		Span<byte> salt = stackalloc byte[SaltSize];
		SystemRandom.Fill(salt);
		return CreateEncryptor(key, salt, context, header);
	}

	/// <summary>
	/// Creates an encryptor with the given salt, so that tests can reproduce known ciphertexts.
	/// </summary>
	public static TCipher CreateEncryptor(ReadOnlySpan<byte> key, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> context, Span<byte> header)
	{
		ValidateKey(key);
		return TCipher.Create(DeriveEncryptor(key, salt, context, header));
	}

	public static TCipher CreateDecryptor(ReadOnlySpan<byte> key, ReadOnlySpan<byte> context, ReadOnlySpan<byte> header)
	{
		ValidateKey(key);
		ArgumentOutOfRangeException.ThrowIfNotEqual(header.Length, HeaderSize, nameof(header));

		if (!TryDeriveDecryptor(key, context, header, out CobblestoneKeys keys))
		{
			throw new AuthenticationTagMismatchException(CommitmentMismatchMessage);
		}

		return TCipher.Create(keys);
	}

	public static void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, ReadOnlySpan<byte> context)
	{
		Span<byte> salt = stackalloc byte[SaltSize];
		SystemRandom.Fill(salt);
		Encrypt(key, salt, plaintext, ciphertext, context);
	}

	/// <summary>
	/// Encrypts a message with the given salt, so that tests can reproduce known ciphertexts.
	/// </summary>
	public static void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, ReadOnlySpan<byte> context)
	{
		ValidateKey(key);
		ciphertext = SliceOutput(ciphertext, GetCiphertextLength(plaintext.Length, nameof(plaintext)), nameof(ciphertext));
		ThrowIfOverlap(plaintext, ciphertext, nameof(ciphertext));

		// The derivation reads the key and context before anything is written.
		using CobblestoneKeys keys = DeriveEncryptor(key, salt, context, ciphertext);
		EncryptChunks(keys, plaintext, ciphertext.Slice(HeaderSize));
	}

	public static bool TryDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, ReadOnlySpan<byte> context)
	{
		ValidateKey(key);

		if (!TryGetPlaintextLength(ciphertext.Length, out long length))
		{
			return false;
		}

		plaintext = SliceOutput(plaintext, length, nameof(plaintext));
		ThrowIfOverlap(ciphertext, plaintext, nameof(plaintext));

		if (!TryDeriveDecryptor(key, context, ciphertext.Slice(0, HeaderSize), out CobblestoneKeys keys))
		{
			plaintext.ZeroMemory();
			return false;
		}

		try
		{
			if (TryDecryptChunks(keys, ciphertext.Slice(HeaderSize), plaintext))
			{
				return true;
			}

			// The chunks before the failing one belong to an invalid message.
			plaintext.ZeroMemory();
			return false;
		}
		finally
		{
			keys.Dispose();
		}
	}

	/// <summary>
	/// Derives the keys of a new message from a validated key and writes its header; the inputs are read before the header is written, so they may overlap it.
	/// </summary>
	[SkipLocalsInit]
	private static CobblestoneKeys DeriveEncryptor(ReadOnlySpan<byte> key, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> context, Span<byte> header)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(salt.Length, SaltSize, nameof(salt));
		ArgumentOutOfRangeException.ThrowIfLessThan(header.Length, HeaderSize, nameof(header));

		using CryptoBuffer<byte> okm = new(stackalloc byte[MaxOkmLength].Slice(0, GetOkmLength(key)));
		Expand(key, salt, context, okm.Span);
		CobblestoneKeys keys = CreateKeys(okm.Span);
		salt.CopyTo(header);
		GetCommitment(okm.Span).CopyTo(header.Slice(SaltSize));
		return keys;
	}

	/// <summary>
	/// Derives the keys of the message that starts with <paramref name="header" />, or fails when its commitment does not match.
	/// </summary>
	[SkipLocalsInit]
	private static bool TryDeriveDecryptor(ReadOnlySpan<byte> key, ReadOnlySpan<byte> context, ReadOnlySpan<byte> header, out CobblestoneKeys keys)
	{
		Debug.Assert(header.Length is HeaderSize);

		using CryptoBuffer<byte> okm = new(stackalloc byte[MaxOkmLength].Slice(0, GetOkmLength(key)));
		Expand(key, header.Slice(0, SaltSize), context, okm.Span);

		if (!FixedTime.Equals(GetCommitment(okm.Span), header.Slice(SaltSize, CommitmentSize)))
		{
			keys = default;
			return false;
		}

		keys = CreateKeys(okm.Span);
		return true;
	}

	/// <summary>
	/// Gets the length of the HKDF-Expand output, which holds the AEAD key, the base nonce and the commitment, for a validated input key, which is as long as the AEAD key.
	/// </summary>
	/// <remarks>The sizes come from the spans, as this code is shared between the instantiations and each use of a static member of <typeparamref name="TCipher" /> costs a runtime lookup.</remarks>
	private static int GetOkmLength(ReadOnlySpan<byte> key)
	{
		return key.Length + NonceSize + CommitmentSize;
	}

	private static CobblestoneKeys CreateKeys(ReadOnlySpan<byte> okm)
	{
		int keySize = okm.Length - NonceSize - CommitmentSize;
		return new CobblestoneKeys(okm.Slice(0, keySize), okm.Slice(keySize, NonceSize));
	}

	private static ReadOnlySpan<byte> GetCommitment(ReadOnlySpan<byte> okm)
	{
		return okm.Slice(okm.Length - CommitmentSize);
	}

	[SkipLocalsInit]
	private static void Expand(ReadOnlySpan<byte> key, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> context, Span<byte> output)
	{
		ReadOnlySpan<byte> prefix = TCipher.InfoPrefix;
		int length = checked(prefix.Length + SaltSize + context.Length);
		using CryptoBuffer<byte> info = CryptoBuffer<byte>.ShouldUsePool(length) ? new CryptoBuffer<byte>(length) : new CryptoBuffer<byte>(stackalloc byte[length]);
		prefix.CopyTo(info.Span);
		salt.CopyTo(info.Span.Slice(prefix.Length));
		context.CopyTo(info.Span.Slice(prefix.Length + SaltSize));

		// The specification takes the input key as the PRK, which is shorter than Hkdf.Expand allows.
		Hkdf.ExpandCore<Sha512Core>(key, output, info.Span);
	}

	private static void ValidateKey(ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, TCipher.KeySize, nameof(key));
	}

	private static Span<byte> SliceOutput(Span<byte> output, long length, string paramName)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(output.Length, length, paramName);
		return output.Slice(0, (int)length);
	}

	private static void ThrowIfOverlap(ReadOnlySpan<byte> input, ReadOnlySpan<byte> output, string paramName)
	{
		if (input.Overlaps(output))
		{
			ThrowHelper.ThrowInputOutputOverlap(paramName);
		}
	}
}
