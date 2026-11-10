using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Hpke;

/// <summary>
/// Provides the sizes of the HPKE algorithms, from RFC 9180, Sections 7.2 and 7.3.
/// </summary>
public static class HpkeAlgorithmExtensions
{
	extension(HpkeKdfId kdf)
	{
		/// <summary>
		/// Gets the output length of the hash, Nh, in bytes. An export is at most 255 times as long.
		/// </summary>
		/// <exception cref="ArgumentOutOfRangeException">The KDF is not supported.</exception>
		public int HashLength => kdf switch
		{
			HpkeKdfId.HkdfSha256 => 32,
			HpkeKdfId.HkdfSha384 => 48,
			HpkeKdfId.HkdfSha512 => 64,
			_ => ThrowUnsupported(nameof(kdf), kdf)
		};
	}

	extension(HpkeAeadId aead)
	{
		/// <summary>
		/// Gets the key size, Nk, in bytes; 0 for <see cref="HpkeAeadId.ExportOnly" />.
		/// </summary>
		/// <exception cref="ArgumentOutOfRangeException">The AEAD is not supported.</exception>
		public int KeySize => aead switch
		{
			HpkeAeadId.Aes128Gcm => 16,
			HpkeAeadId.Aes256Gcm or HpkeAeadId.ChaCha20Poly1305 => 32,
			HpkeAeadId.ExportOnly => 0,
			_ => ThrowUnsupported(nameof(aead), aead)
		};

		/// <summary>
		/// Gets the nonce size, Nn, in bytes; 0 for <see cref="HpkeAeadId.ExportOnly" />.
		/// </summary>
		/// <exception cref="ArgumentOutOfRangeException">The AEAD is not supported.</exception>
		public int NonceSize => aead switch
		{
			HpkeAeadId.Aes128Gcm or HpkeAeadId.Aes256Gcm or HpkeAeadId.ChaCha20Poly1305 => 12,
			HpkeAeadId.ExportOnly => 0,
			_ => ThrowUnsupported(nameof(aead), aead)
		};

		/// <summary>
		/// Gets the size of the authentication tag, Nt, in bytes, by which a ciphertext exceeds its plaintext; 0 for <see cref="HpkeAeadId.ExportOnly" />.
		/// </summary>
		/// <exception cref="ArgumentOutOfRangeException">The AEAD is not supported.</exception>
		public int TagSize => aead switch
		{
			HpkeAeadId.Aes128Gcm or HpkeAeadId.Aes256Gcm or HpkeAeadId.ChaCha20Poly1305 => 16,
			HpkeAeadId.ExportOnly => 0,
			_ => ThrowUnsupported(nameof(aead), aead)
		};
	}

	[DoesNotReturn]
	private static int ThrowUnsupported<T>(string parameterName, T value) where T : struct, Enum
	{
		throw new ArgumentOutOfRangeException(parameterName, value, $"The {typeof(T).Name} value is not supported.");
	}
}
