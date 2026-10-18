using CryptoBase.Ciphers.Streams;

namespace CryptoBase.Ciphers.Aead;

/// <summary>
/// Provides XChaCha20-Poly1305 authenticated encryption.
/// </summary>
public sealed class XChaCha20Poly1305Cipher : IAeadCipher<XChaCha20Poly1305Cipher>
{
	/// <summary>The required key size, in bytes.</summary>
	public const int KeySize = XChaCha20Cipher.KeySize;

	/// <inheritdoc />
	public static XChaCha20Poly1305Cipher Create(scoped ReadOnlySpan<byte> key)
	{
		return new XChaCha20Poly1305Cipher(key);
	}

	/// <inheritdoc />
	public static int NonceSize => XChaCha20Cipher.IVSize;

	/// <inheritdoc />
	public static int TagSize => 16;

	private readonly SubkeyCipher _chacha20;

	/// <summary>
	/// Initializes a new instance with the specified key.
	/// </summary>
	/// <param name="key">The 32-byte key.</param>
	public XChaCha20Poly1305Cipher(ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeySize, nameof(key));

		_chacha20 = new SubkeyCipher(key);
	}

	/// <inheritdoc />
	public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
	{
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, NonceSize, TagSize);
		destination = destination.Slice(0, source.Length);

		_chacha20.InitializeXChaCha20Nonce(nonce);
		ChaCha20Poly1305Utils.EncryptAndComputeTag(_chacha20, source, destination, tag, associatedData);
	}

	/// <inheritdoc />
	public bool TryDecrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData = default)
	{
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, NonceSize, TagSize);
		destination = destination.Slice(0, source.Length);

		_chacha20.InitializeXChaCha20Nonce(nonce);
		return ChaCha20Poly1305Utils.TryDecrypt(_chacha20, source, tag, destination, associatedData);
	}

	/// <inheritdoc />
	public void Dispose()
	{
		_chacha20.Dispose();
	}

	// XChaCha20-Poly1305 is ChaCha20-Poly1305 with the HChaCha20 subkey and a nonce of four zero bytes followed by nonce[16..24], so it reuses the IETF ChaCha20 core.
	private sealed class SubkeyCipher : ChaCha20Cipher
	{
		private Vector256<byte> _key;

		internal SubkeyCipher(ReadOnlySpan<byte> key)
		{
			_key = Vector256.LoadUnsafe(ref MemoryMarshal.GetReference(key));
		}

		/// <summary>Derives the subkey for <paramref name="nonce" /> and resets the block counter to zero.</summary>
		internal void InitializeXChaCha20Nonce(ReadOnlySpan<byte> nonce)
		{
			Debug.Assert(nonce.Length is XChaCha20Cipher.IVSize);

			Span<uint> state = StateSpan;
			Sigma32.CopyTo(state);
			ChaCha20Utils.DeriveXChaCha20Key(ref StateRef, ref Unsafe.As<Vector256<byte>, byte>(ref _key), ref MemoryMarshal.GetReference(nonce));
			state[13] = 0;
			MemoryMarshal.Cast<byte, uint>(nonce.Slice(16, 8)).CopyTo(state.Slice(14));
			SetCounter(0);
		}

		public override void Dispose()
		{
			_key.ZeroMemory();
			base.Dispose();
		}
	}
}
