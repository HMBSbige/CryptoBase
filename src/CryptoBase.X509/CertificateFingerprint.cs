using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace CryptoBase.X509;

/// <summary>
/// Represents a certificate fingerprint (RFC 8122, Sec. 5): a hash function and the digest with it of a certificate's DER encoding, as the SDP fingerprint attribute carries them.
/// </summary>
/// <remarks>
/// <para>
/// An SDP token (RFC 4566, Sec. 9) names the hash function. The names of the Hash Function Textual Names registry, "sha-1", "sha-224", "sha-256", "sha-384", "sha-512", "md5" and "md2", in letters of either case, name the registered hash functions, whose <see cref="HashAlgorithm" /> is <see cref="HashAlgorithmName.SHA1" />, <c>SHA224</c>, <see cref="HashAlgorithmName.SHA256" />, <see cref="HashAlgorithmName.SHA384" />, <see cref="HashAlgorithmName.SHA512" />, <see cref="HashAlgorithmName.MD5" /> or <c>MD2</c>, and whose digests must have their lengths.
/// Any other token names a hash function that is not registered, whose <see cref="HashAlgorithm" /> is the token as it is, and whose digest must not be empty.
/// </para>
/// <para>
/// The constructor also takes the <see cref="HashAlgorithm" /> of a registered hash function, such as <see cref="HashAlgorithmName.SHA256" />, for that function. <see cref="Parse" /> does not: there a token such as SHA256, which is such a name but not a registered name, is invalid.
/// So <see cref="HashAlgorithm" /> tells the hash functions apart, and <c>CertificateFingerprint.Parse(fingerprint.ToString())</c> and <c>new CertificateFingerprint(fingerprint.HashAlgorithm, fingerprint.Digest.Span)</c> have the hash function and digest of <c>fingerprint</c>.
/// </para>
/// <para>
/// An instance holds its own copy of the digest. Instances are immutable, so they may be used concurrently.
/// </para>
/// </remarks>
public sealed class CertificateFingerprint
{
	private static readonly (string Name, HashAlgorithmName Algorithm, int Length)[] Registered =
	[
		("sha-1", HashAlgorithmName.SHA1, 20),
		("sha-224", new HashAlgorithmName("SHA224"), 28),
		("sha-256", HashAlgorithmName.SHA256, 32),
		("sha-384", HashAlgorithmName.SHA384, 48),
		("sha-512", HashAlgorithmName.SHA512, 64),
		("md5", HashAlgorithmName.MD5, 16),
		("md2", new HashAlgorithmName("MD2"), 16),
	];

	/// <summary>
	/// Initializes a fingerprint.
	/// </summary>
	/// <param name="hashAlgorithm">The hash function: a registered name in letters of either case, such as <c>sha-256</c>, the <see cref="HashAlgorithm" /> of a registered hash function, such as <see cref="HashAlgorithmName.SHA256" />, or another SDP token, which names a hash function that is not registered.</param>
	/// <param name="digest">The digest of the certificate's DER encoding with <paramref name="hashAlgorithm" />; the instance holds a copy.</param>
	/// <exception cref="ArgumentException"><paramref name="hashAlgorithm" /> is not an SDP token, or <paramref name="digest" /> does not have the length of a registered hash function, or is empty.</exception>
	public CertificateFingerprint(HashAlgorithmName hashAlgorithm, ReadOnlySpan<byte> digest)
	{
		if (hashAlgorithm.Name is not { } name || !IsToken(name))
		{
			throw new ArgumentException("The hash algorithm is not an SDP token.", nameof(hashAlgorithm));
		}

		int index = IndexOfName(name);

		if (index < 0)
		{
			index = IndexOfAlgorithm(name);
		}

		if (index < 0 ? digest.IsEmpty : digest.Length != Registered[index].Length)
		{
			throw new ArgumentException("The digest does not have the length of the hash function.", nameof(digest));
		}

		HashAlgorithm = index < 0 ? hashAlgorithm : Registered[index].Algorithm;
		Digest = digest.ToArray();
	}

	/// <summary>
	/// Gets the hash function: that of a registered hash function, or the token that names another.
	/// </summary>
	public HashAlgorithmName HashAlgorithm { get; }

	/// <summary>
	/// Gets the digest of the certificate's DER encoding.
	/// </summary>
	public ReadOnlyMemory<byte> Digest { get; }

	/// <summary>
	/// Decodes the value of an SDP fingerprint attribute (RFC 8122, Sec. 5), the text after <c>a=fingerprint:</c>, such as <c>sha-256 12:DF:3E:…</c>.
	/// </summary>
	/// <remarks>
	/// The value is a hash function, one space, and each byte of the digest as two hexadecimal digits, separated by colons, with nothing before or after.
	/// The hash function is a registered name, compared without regard to case as ABNF strings are (RFC 5234, Sec. 2.3), or another SDP token, which names a hash function that is not registered, unless it is the <see cref="HashAlgorithm" /> of a registered hash function, such as SHA256.
	/// The grammar asks for uppercase digits; lowercase ones are accepted too, as they give the same digest.
	/// </remarks>
	/// <param name="value">The attribute value.</param>
	/// <returns>The fingerprint.</returns>
	/// <exception cref="FormatException"><paramref name="value" /> does not follow the grammar, its hash function is the <see cref="HashAlgorithm" /> of a registered hash function but not a registered name, or its digest does not have the length of its registered hash function.</exception>
	public static CertificateFingerprint Parse(ReadOnlySpan<char> value)
	{
		return TryParse(value, out CertificateFingerprint? fingerprint) ? fingerprint : throw new FormatException("The value is not a fingerprint attribute value of RFC 8122.");
	}

	/// <summary>
	/// Decodes the value of an SDP fingerprint attribute, as <see cref="Parse" /> does.
	/// </summary>
	/// <param name="value">The attribute value.</param>
	/// <param name="fingerprint">When this method returns <see langword="true" />, the fingerprint; otherwise, <see langword="null" />.</param>
	/// <returns><see langword="true" /> if <paramref name="value" /> is a fingerprint; otherwise, <see langword="false" />.</returns>
	public static bool TryParse(ReadOnlySpan<char> value, [NotNullWhen(true)] out CertificateFingerprint? fingerprint)
	{
		fingerprint = null;
		int space = value.IndexOf(' ');

		if (space < 0)
		{
			return false;
		}

		ReadOnlySpan<char> name = value.Slice(0, space);
		ReadOnlySpan<char> hex = value.Slice(space + 1);

		// Two digits per byte and a colon between bytes.
		if (!IsToken(name) || hex.Length % 3 is not 2)
		{
			return false;
		}

		int index = IndexOfName(name);

		// A hash function that is not registered cannot have the HashAlgorithm of a registered one.
		if (index < 0 && IndexOfAlgorithm(name) >= 0)
		{
			return false;
		}

		byte[] digest = new byte[(hex.Length + 1) / 3];

		for (int i = 0; i < digest.Length; ++i)
		{
			ReadOnlySpan<char> pair = hex.Slice(3 * i, 2);

			if (!char.IsAsciiHexDigit(pair[0]) || !char.IsAsciiHexDigit(pair[1]) || i > 0 && hex[3 * i - 1] is not ':')
			{
				return false;
			}

			digest[i] = (byte)(HexValue(pair[0]) << 4 | HexValue(pair[1]));
		}

		if (index >= 0 && digest.Length != Registered[index].Length)
		{
			return false;
		}

		fingerprint = new CertificateFingerprint(index < 0 ? new HashAlgorithmName(name.ToString()) : Registered[index].Algorithm, digest);
		return true;
	}

	/// <summary>
	/// Returns the value of an SDP fingerprint attribute for the fingerprint: the registered name of the hash function, in lower case, or the token that names another, a space, and the digest in uppercase hexadecimal digits separated by colons.
	/// </summary>
	/// <returns>The attribute value, such as <c>sha-256 12:DF:3E:…</c>, which <see cref="Parse" /> decodes to the hash function and digest of the instance.</returns>
	public override string ToString()
	{
		string hex = Convert.ToHexString(Digest.Span);
		StringBuilder builder = new(TextualName(HashAlgorithm), hex.Length * 3 / 2 + 16);

		for (int i = 0; i < hex.Length; i += 2)
		{
			builder.Append(i is 0 ? ' ' : ':').Append(hex, i, 2);
		}

		return builder.ToString();
	}

	// The registered name of a registered hash function, or the token of another.
	internal static string TextualName(HashAlgorithmName hashAlgorithm)
	{
		foreach ((string name, HashAlgorithmName algorithm, _) in Registered)
		{
			if (algorithm == hashAlgorithm)
			{
				return name;
			}
		}

		return hashAlgorithm.Name ?? "";
	}

	// The index in Registered of a registered name, compared without regard to case as ABNF strings are (RFC 5234, Sec. 2.3), or -1.
	private static int IndexOfName(ReadOnlySpan<char> name)
	{
		for (int i = 0; i < Registered.Length; ++i)
		{
			if (Ascii.EqualsIgnoreCase(name, Registered[i].Name))
			{
				return i;
			}
		}

		return -1;
	}

	// The index in Registered of the HashAlgorithm of a registered hash function, compared ordinally as HashAlgorithmName compares, or -1.
	private static int IndexOfAlgorithm(ReadOnlySpan<char> name)
	{
		for (int i = 0; i < Registered.Length; ++i)
		{
			if (name.SequenceEqual(Registered[i].Algorithm.Name))
			{
				return i;
			}
		}

		return -1;
	}

	// token-char = %x21 / %x23-27 / %x2A-2B / %x2D-2E / %x30-39 / %x41-5A / %x5E-7E (RFC 4566, Sec. 9).
	private static bool IsToken(ReadOnlySpan<char> value)
	{
		if (value.IsEmpty)
		{
			return false;
		}

		foreach (char c in value)
		{
			if (c is not ('\x21' or >= '\x23' and <= '\x27' or '\x2A' or '\x2B' or '\x2D' or '\x2E' or >= '\x30' and <= '\x39' or >= '\x41' and <= '\x5A' or >= '\x5E' and <= '\x7E'))
			{
				return false;
			}
		}

		return true;
	}

	private static int HexValue(char c)
	{
		return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10;
	}
}
