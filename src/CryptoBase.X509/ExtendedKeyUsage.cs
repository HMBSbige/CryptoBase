using System.Collections.Immutable;

namespace CryptoBase.X509;

/// <summary>
/// Represents the value of an extended key usage extension (RFC 5280, Sec. 4.2.1.12): the purposes for which the subject's key may be used.
/// </summary>
/// <remarks>
/// <para>
/// Decoding accepts only DER and requires at least one KeyPurposeId.
/// </para>
/// <para>
/// Instances are immutable, so they may be used concurrently.
/// </para>
/// </remarks>
public sealed class ExtendedKeyUsage
{
	/// <summary>
	/// The KeyPurposeId anyExtendedKeyUsage, with which a certification authority does not restrict the purposes of the key.
	/// </summary>
	public const string AnyExtendedKeyUsage = "2.5.29.37.0";

	/// <summary>
	/// The KeyPurposeId id-kp-serverAuth, the purpose of <see cref="CertificateUsage.ServerAuthentication" />.
	/// </summary>
	public const string ServerAuthentication = "1.3.6.1.5.5.7.3.1";

	/// <summary>
	/// The KeyPurposeId id-kp-clientAuth, the purpose of <see cref="CertificateUsage.ClientAuthentication" />.
	/// </summary>
	public const string ClientAuthentication = "1.3.6.1.5.5.7.3.2";

	/// <summary>
	/// The KeyPurposeId id-kp-OCSPSigning, with which a certification authority designates a delegated OCSP responder (RFC 6960, Sec. 4.2.2.2).
	/// </summary>
	public const string OcspSigning = "1.3.6.1.5.5.7.3.9";

	// What Purposes boxes, which Contains searches without allocating an enumerator.
	private readonly ImmutableArray<string> _purposes;

	private ExtendedKeyUsage(ImmutableArray<string> purposes)
	{
		_purposes = purposes;
		Purposes = purposes;
	}

	/// <summary>
	/// Gets the KeyPurposeIds as dotted-decimal object identifiers, in the order of the encoding, repeats included.
	/// </summary>
	public IReadOnlyList<string> Purposes { get; }

	/// <summary>
	/// Decodes the DER-encoded value of an extended key usage extension.
	/// </summary>
	/// <param name="source">The contents of extnValue, an ExtKeyUsageSyntax, with nothing after it.</param>
	/// <returns>The decoded value.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> is not a DER-encoded ExtKeyUsageSyntax.</exception>
	public static ExtendedKeyUsage Decode(ReadOnlySpan<byte> source)
	{
		try
		{
			return Read(source.ToArray());
		}
		catch (AsnContentException e)
		{
			throw new ArgumentException("The extended key usage is invalid.", nameof(source), e);
		}
	}

	/// <summary>
	/// Determines whether the extension lists a purpose.
	/// </summary>
	/// <remarks>
	/// Only the purpose itself is looked for: <see cref="AnyExtendedKeyUsage" /> is a purpose like the others, and whether it stands for one that is absent is for the caller to decide.
	/// </remarks>
	/// <param name="purpose">The KeyPurposeId as a dotted-decimal object identifier, such as <see cref="ServerAuthentication" />.</param>
	/// <returns><see langword="true" /> if <see cref="Purposes" /> holds <paramref name="purpose" />; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="purpose" /> is <see langword="null" />.</exception>
	public bool Contains(string purpose)
	{
		ArgumentNullException.ThrowIfNull(purpose);

		return _purposes.AsSpan().Contains(purpose);
	}

	// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId, and KeyPurposeId ::= OBJECT IDENTIFIER.
	internal static ExtendedKeyUsage Read(ReadOnlyMemory<byte> value)
	{
		return new ExtendedKeyUsage([.. DerReader.ReadSoleSequenceOf(value, static (ref sequence) => sequence.ReadObjectIdentifier())]);
	}
}
