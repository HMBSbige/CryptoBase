using CryptoBase.Kdf.Argon2;

namespace CryptoBase.Kdf;

/// <summary>
/// Implements Argon2d version 0x13, as specified by RFC 9106.
/// Its memory accesses depend on the password, so it suits only applications without side-channel timing threats, such as proof of work; RFC 9106 makes Argon2id the primary variant.
/// </summary>
/// <remarks>
/// The working memory is wiped before each method returns, and up to 256 MiB of it in total is then kept for a few seconds for reuse.
/// </remarks>
public static class Argon2d
{
	/// <summary>
	/// Derives key material from a password using Argon2d.
	/// </summary>
	/// <param name="password">The password.</param>
	/// <param name="salt">The salt. RFC 9106 recommends 16 bytes for password hashing.</param>
	/// <param name="destination">The buffer that receives the derived key.</param>
	/// <param name="parameters">The cost parameters.</param>
	/// <param name="secret">The secret key, also known as a pepper.</param>
	/// <param name="associatedData">The associated data.</param>
	/// <param name="maxDegreeOfParallelism">
	/// The maximum number of threads that fill the lanes, the calling thread included, or -1 for no limit; the other threads come from the thread pool. It never changes the derived key.
	/// </param>
	/// <exception cref="ArgumentOutOfRangeException">
	/// <paramref name="destination" /> is shorter than 4 bytes, or <paramref name="maxDegreeOfParallelism" /> is 0 or less than -1.
	/// </exception>
	/// <exception cref="ArgumentException"><paramref name="parameters" /> is the default value.</exception>
	public static void DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> destination, Argon2Parameters parameters, ReadOnlySpan<byte> secret = default, ReadOnlySpan<byte> associatedData = default, int maxDegreeOfParallelism = -1)
	{
		Argon2Core.ThrowIfInvalidArguments(destination, parameters, maxDegreeOfParallelism);
		Argon2Core.DeriveKey(password, salt, secret, associatedData, Argon2Type.Argon2d, parameters, maxDegreeOfParallelism, destination);
	}
}
