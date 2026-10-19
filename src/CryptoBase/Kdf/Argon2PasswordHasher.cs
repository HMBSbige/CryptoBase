using CryptoBase.Kdf.Argon2;

namespace CryptoBase.Kdf;

/// <summary>
/// Hashes and verifies passwords with Argon2 version 0x13, storing each hash in the PHC string format of the Argon2 reference implementation.
/// </summary>
/// <remarks>
/// <para>
/// A hash string looks like <c>$argon2id$v=19$m=65536,t=3,p=4$&lt;salt&gt;$&lt;hash&gt;</c>, with the salt and the hash in standard Base64 without padding.
/// It does not hold the secret, which must be supplied again.
/// </para>
/// <para>
/// Parsing is strict: the version must be 19; the parameters must be exactly <c>m</c>, <c>t</c> and <c>p</c> in that order, in decimal without leading zeros and within the ranges of <see cref="Argon2Parameters" />;
/// the salt must be at least 8 bytes long and the hash at least 4 bytes long. The optional <c>keyid</c> and <c>data</c> parameters are not supported.
/// </para>
/// <para>
/// Verification costs as much time and memory as the string specifies, so verify only strings from trusted storage.
/// </para>
/// </remarks>
public static class Argon2PasswordHasher
{
	private const int DefaultSaltLength = 16;
	private const int DefaultHashLength = 32;

	/// <summary>
	/// Hashes a password with a random salt.
	/// </summary>
	/// <param name="password">The password.</param>
	/// <param name="parameters">The cost parameters.</param>
	/// <param name="type">The type of Argon2. RFC 9106 recommends <see cref="Argon2Type.Argon2id" />.</param>
	/// <param name="saltLength">The length of the random salt, in bytes. It must be at least 8; RFC 9106 recommends 16.</param>
	/// <param name="hashLength">The length of the hash, in bytes. It must be at least 4.</param>
	/// <param name="secret">The secret key, also known as a pepper, which is not stored in the string.</param>
	/// <returns>The hash string.</returns>
	/// <exception cref="ArgumentOutOfRangeException">
	/// <paramref name="type" /> is not a defined value, <paramref name="saltLength" /> is less than 8, or <paramref name="hashLength" /> is less than 4.
	/// </exception>
	/// <exception cref="ArgumentException"><paramref name="parameters" /> is the default value.</exception>
	public static string Hash(ReadOnlySpan<byte> password, Argon2Parameters parameters, Argon2Type type, int saltLength = DefaultSaltLength, int hashLength = DefaultHashLength, ReadOnlySpan<byte> secret = default)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(saltLength, Argon2PhcString.MinSaltLength);
		ThrowIfInvalid(parameters, type, hashLength);

		using CryptoBuffer<byte> saltBuffer = CryptoBuffer<byte>.ShouldUsePool(saltLength) ? new CryptoBuffer<byte>(saltLength) : new CryptoBuffer<byte>(stackalloc byte[saltLength]);
		Span<byte> salt = saltBuffer.Span;
		SystemRandom.Fill(salt);

		return Hash(password, salt, parameters, type, hashLength, secret);
	}

	/// <summary>
	/// Hashes a password with the specified salt.
	/// </summary>
	/// <param name="password">The password.</param>
	/// <param name="salt">The salt, which must be unique for each password and at least 8 bytes long; RFC 9106 recommends 16 bytes.</param>
	/// <param name="parameters">The cost parameters.</param>
	/// <param name="type">The type of Argon2. RFC 9106 recommends <see cref="Argon2Type.Argon2id" />.</param>
	/// <param name="hashLength">The length of the hash, in bytes. It must be at least 4.</param>
	/// <param name="secret">The secret key, also known as a pepper, which is not stored in the string.</param>
	/// <returns>The hash string.</returns>
	/// <exception cref="ArgumentOutOfRangeException">
	/// <paramref name="salt" /> is shorter than 8 bytes, <paramref name="type" /> is not a defined value, or <paramref name="hashLength" /> is less than 4.
	/// </exception>
	/// <exception cref="ArgumentException"><paramref name="parameters" /> is the default value.</exception>
	public static string Hash(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Argon2Parameters parameters, Argon2Type type, int hashLength = DefaultHashLength, ReadOnlySpan<byte> secret = default)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(salt.Length, Argon2PhcString.MinSaltLength, nameof(salt));
		ThrowIfInvalid(parameters, type, hashLength);

		using CryptoBuffer<byte> hashBuffer = CryptoBuffer<byte>.ShouldUsePool(hashLength) ? new CryptoBuffer<byte>(hashLength) : new CryptoBuffer<byte>(stackalloc byte[hashLength]);
		Span<byte> hash = hashBuffer.Span;
		Argon2Core.DeriveKey(password, salt, secret, default, type, parameters, -1, hash);

		return Argon2PhcString.Format(type, parameters, salt, hash);
	}

	/// <summary>
	/// Verifies a password against a hash string.
	/// </summary>
	/// <param name="password">The password.</param>
	/// <param name="encoded">The hash string.</param>
	/// <param name="secret">The secret key the hash was computed with, if any.</param>
	/// <returns><see langword="true" /> if the password and the secret match the hash; otherwise, <see langword="false" />.</returns>
	/// <exception cref="FormatException"><paramref name="encoded" /> is not a valid or supported hash string.</exception>
	public static bool Verify(ReadOnlySpan<byte> password, ReadOnlySpan<char> encoded, ReadOnlySpan<byte> secret = default)
	{
		Argon2PhcString phcString = Argon2PhcString.Parse(encoded);
		int saltLength = phcString.SaltLength;
		int hashLength = phcString.HashLength;

		using CryptoBuffer<byte> saltBuffer = CryptoBuffer<byte>.ShouldUsePool(saltLength) ? new CryptoBuffer<byte>(saltLength) : new CryptoBuffer<byte>(stackalloc byte[saltLength]);
		using CryptoBuffer<byte> expectedBuffer = CryptoBuffer<byte>.ShouldUsePool(hashLength) ? new CryptoBuffer<byte>(hashLength) : new CryptoBuffer<byte>(stackalloc byte[hashLength]);
		using CryptoBuffer<byte> actualBuffer = CryptoBuffer<byte>.ShouldUsePool(hashLength) ? new CryptoBuffer<byte>(hashLength) : new CryptoBuffer<byte>(stackalloc byte[hashLength]);
		Span<byte> salt = saltBuffer.Span;
		Span<byte> expected = expectedBuffer.Span;
		Span<byte> actual = actualBuffer.Span;

		phcString.DecodeSalt(salt);
		phcString.DecodeHash(expected);
		Argon2Core.DeriveKey(password, salt, secret, default, phcString.Type, phcString.Parameters, -1, actual);

		return CryptographicOperations.FixedTimeEquals(actual, expected);
	}

	/// <summary>
	/// Determines whether a hash string was computed with settings other than the specified ones, so that the password should be hashed again once verified.
	/// </summary>
	/// <param name="encoded">The hash string.</param>
	/// <param name="parameters">The cost parameters new hashes use.</param>
	/// <param name="type">The type of Argon2 new hashes use.</param>
	/// <param name="hashLength">The length of new hashes, in bytes.</param>
	/// <returns><see langword="true" /> if the type, the parameters or the hash length differ; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="type" /> is not a defined value, or <paramref name="hashLength" /> is less than 4.</exception>
	/// <exception cref="ArgumentException"><paramref name="parameters" /> is the default value.</exception>
	/// <exception cref="FormatException"><paramref name="encoded" /> is not a valid or supported hash string.</exception>
	public static bool NeedsRehash(ReadOnlySpan<char> encoded, Argon2Parameters parameters, Argon2Type type, int hashLength = DefaultHashLength)
	{
		ThrowIfInvalid(parameters, type, hashLength);

		Argon2PhcString phcString = Argon2PhcString.Parse(encoded);
		return phcString.Type != type || phcString.Parameters != parameters || phcString.HashLength != hashLength;
	}

	private static void ThrowIfInvalid(Argon2Parameters parameters, Argon2Type type, int hashLength)
	{
		Argon2Core.ThrowIfDefault(parameters);
		ArgumentOutOfRangeException.ThrowIfLessThan(hashLength, Argon2Core.MinTagLength);

		if (type is not (Argon2Type.Argon2d or Argon2Type.Argon2i or Argon2Type.Argon2id))
		{
			throw new ArgumentOutOfRangeException(nameof(type), type, "The type must be Argon2d, Argon2i or Argon2id.");
		}
	}
}
