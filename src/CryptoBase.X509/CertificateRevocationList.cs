using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace CryptoBase.X509;

/// <summary>
/// Represents an X.509 certificate revocation list (RFC 5280, Sec. 5).
/// </summary>
/// <remarks>
/// <para>
/// Decoding accepts only DER and checks the structure of RFC 5280, Sec. 5.1: a CRL with extensions or entry extensions must be version 2, an extension may appear only once in a list, and the serial numbers must be distinct.
/// The reason code and invalidity date entry extensions must decode, and a reason must be one that RFC 5280, Sec. 5.3.1, defines. The CRL extensions decode on first use instead, so the methods that return them report a malformed one.
/// </para>
/// <para>
/// Decoding does not check the signature, whether the CRL is current, or whether it is complete.
/// </para>
/// <para>
/// Instances are immutable, so they may be used concurrently.
/// </para>
/// </remarks>
public sealed class CertificateRevocationList
{
	private const string PemLabel = "X509 CRL";
	internal const string ReasonCodeOid = "2.5.29.21";
	internal const string InvalidityDateOid = "2.5.29.24";

	private static readonly Asn1Tag ExtensionsTag = new(TagClass.ContextSpecific, 0, true);

	// The contents of revokedCertificates.
	private readonly ReadOnlyMemory<byte> _entries;

	// The index of _entries, by serial number. Each slot holds the hash of the number in its upper half and one more than the offset of the entry in its lower half, zero being free; a slot's position is the scaled hash, and collisions take the next free slot.
	private readonly ulong[] _slots;

	private SignatureCheck? _lastSignatureCheck;

	private CertificateRevocationList(ReadOnlyMemory<byte> encoded)
	{
		Encoded = encoded;
		DerReader crl = DerReader.ReadSoleSequence(encoded);

		DerReader tbs = crl.ReadSequence(out ReadOnlyMemory<byte> tbsCertList);
		TbsCertList = tbsCertList;
		SignatureAlgorithm = AlgorithmIdentifier.Read(ref crl);
		Signature = crl.ReadBitString();
		crl.ThrowIfNotEmpty();

		Version = 1;

		// Sec. 5.1.2.1: DER has no default to omit here, as the field is OPTIONAL; if present, it must be v2.
		if (tbs.PeekTagIs(Asn1Tag.Integer))
		{
			Version = tbs.ReadInt32() is 1 ? 2 : throw new AsnContentException();
		}

		// The outer signature algorithm is an AlgorithmIdentifier, so the same bytes are one.
		if (!tbs.ReadEncodedValue().Span.SequenceEqual(SignatureAlgorithm.Encoded.Span))
		{
			throw new AsnContentException();
		}

		Issuer = X509Name.Read(ref tbs);
		ThisUpdate = X509Time.Read(ref tbs);

		if (tbs.PeekTagIs(Asn1Tag.UtcTime) || tbs.PeekTagIs(Asn1Tag.GeneralizedTime))
		{
			NextUpdate = X509Time.Read(ref tbs);
		}

		_slots = [];

		if (tbs.PeekTagIs(Asn1Tag.Sequence))
		{
			DerReader entries = tbs.ReadSequence();
			_entries = entries.GetRemaining();
			RevokedCount = CountEntries(entries);
			_slots = RevokedCount is 0 ? [] : new ulong[RevokedCount * 2];
			ReadEntries(entries);
		}

		if (tbs.PeekTagIs(ExtensionsTag))
		{
			if (Version is not 2)
			{
				throw new AsnContentException();
			}

			Extensions = CertificateExtension.ReadList(ref tbs, ExtensionsTag);
		}
		else
		{
			Extensions = [];
		}

		tbs.ThrowIfNotEmpty();
	}

	/// <summary>
	/// Gets the DER encoding of the whole CRL.
	/// </summary>
	public ReadOnlyMemory<byte> Encoded { get; }

	/// <summary>
	/// Gets the DER encoding of the TBSCertList, which the signature covers.
	/// </summary>
	public ReadOnlyMemory<byte> TbsCertList { get; }

	/// <summary>
	/// Gets the version: 1 or 2.
	/// </summary>
	public int Version { get; }

	/// <summary>
	/// Gets the DER encoding of the issuer Name.
	/// </summary>
	public ReadOnlyMemory<byte> Issuer { get; }

	/// <summary>
	/// Gets the issue date of the CRL, in UTC.
	/// </summary>
	public DateTimeOffset ThisUpdate { get; }

	/// <summary>
	/// Gets the date by which the next CRL will be issued, in UTC, or <see langword="null" /> if the field is absent.
	/// </summary>
	public DateTimeOffset? NextUpdate { get; }

	/// <summary>
	/// Gets the number of entries of revokedCertificates.
	/// </summary>
	public int RevokedCount { get; }

	/// <summary>
	/// Gets the CRL extensions, in the order of the encoding; empty if there are none.
	/// </summary>
	public IReadOnlyList<CertificateExtension> Extensions { get; }

	/// <summary>
	/// Gets the algorithm of the issuer's signature.
	/// </summary>
	public AlgorithmIdentifier SignatureAlgorithm { get; }

	/// <summary>
	/// Gets the issuer's signature, the bytes of its BIT STRING.
	/// </summary>
	public ReadOnlyMemory<byte> Signature { get; }

	// Whether an entry has a critical extension other than a reason code or an invalidity date, for which RFC 5280, Sec. 5.3, forbids using the CRL at all.
	internal bool HasUnrecognizedCriticalEntryExtension { get; private set; }

	// The extensions that decode on first use. Threads that race decode them alike, and all use the instance stored first.
	internal DecodedCrlExtensions DecodedExtensions
	{
		get
		{
			if (Volatile.Read(ref field) is { } decoded)
			{
				return decoded;
			}

			DecodedCrlExtensions created = new(Extensions);
			return Interlocked.CompareExchange(ref field, created, null) ?? created;
		}
	}

	/// <summary>
	/// Decodes a DER-encoded CRL.
	/// </summary>
	/// <param name="source">The CRL, with nothing after it.</param>
	/// <returns>The CRL, which holds a copy of <paramref name="source" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> is not a DER-encoded CRL.</exception>
	public static CertificateRevocationList Decode(ReadOnlySpan<byte> source)
	{
		return Decode(source.ToArray(), nameof(source));
	}

	/// <summary>
	/// Decodes the first PEM block (RFC 7468) labeled X509 CRL in a text.
	/// </summary>
	/// <remarks>Other blocks and the text around the blocks are ignored.</remarks>
	/// <param name="source">The text.</param>
	/// <returns>The CRL.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> has no X509 CRL block, or the first one is not a DER-encoded CRL.</exception>
	public static CertificateRevocationList DecodePem(ReadOnlySpan<char> source)
	{
		return Decode(X509PemReader.ReadFirst(source, PemLabel, nameof(source)), nameof(source));
	}

	/// <summary>
	/// Decodes every PEM block (RFC 7468) labeled X509 CRL in a text.
	/// </summary>
	/// <remarks>Other blocks and the text around the blocks are ignored.</remarks>
	/// <param name="source">The text.</param>
	/// <returns>The CRLs, in the order of the text; empty if there are none.</returns>
	/// <exception cref="ArgumentException">An X509 CRL block is not a DER-encoded CRL.</exception>
	public static CertificateRevocationList[] DecodePemAll(ReadOnlySpan<char> source)
	{
		return X509PemReader.ReadAll(source, PemLabel, static encoded => Decode(encoded, nameof(source)));
	}

	/// <summary>
	/// Verifies the issuer's signature on the TBSCertList.
	/// </summary>
	/// <remarks>To tell an algorithm that the package does not support from a wrong signature, call <see cref="AlgorithmIdentifier.TryGetSignatureAlgorithm" /> on <see cref="SignatureAlgorithm" />.</remarks>
	/// <param name="issuerKey">The issuer's public key.</param>
	/// <returns><see langword="true" /> if <see cref="SignatureAlgorithm" /> names a signature algorithm that <paramref name="issuerKey" /> supports and the signature is valid with it; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="issuerKey" /> is <see langword="null" />.</exception>
	/// <exception cref="ObjectDisposedException"><paramref name="issuerKey" /> has been disposed.</exception>
	public bool VerifySignature(ISignatureKey issuerKey)
	{
		ArgumentNullException.ThrowIfNull(issuerKey);

		return SignatureAlgorithm.VerifySignature(issuerKey, TbsCertList.Span, Signature.Span);
	}

	// Kept for the last key asked about: a long CRL covers many certificates, and should not be hashed for each.
	// Only a verification is kept: whether a key supports the algorithm depends on its implementation, which may differ for the same SubjectPublicKeyInfo.
	internal bool VerifySignature(ISignatureKey issuerKey, ReadOnlyMemory<byte> issuerPublicKeyInfo)
	{
		if (!SignatureAlgorithm.TryGetSignatureAlgorithm(out SignatureAlgorithm algorithm) || !issuerKey.Supports(algorithm))
		{
			return false;
		}

		if (Volatile.Read(ref _lastSignatureCheck) is { } last && last.PublicKeyInfo.Span.SequenceEqual(issuerPublicKeyInfo.Span))
		{
			return last.Valid;
		}

		bool valid = issuerKey.Verify(algorithm, TbsCertList.Span, Signature.Span);
		Volatile.Write(ref _lastSignatureCheck, new SignatureCheck(issuerPublicKeyInfo, valid));
		return valid;
	}

	/// <summary>
	/// Finds the entry of a serial number.
	/// </summary>
	/// <remarks>Calls may be concurrent.</remarks>
	/// <param name="serialNumber">The big-endian two's-complement contents of the number's INTEGER, as those of <see cref="Certificate.SerialNumber" />; they must be minimal, as DER makes them, to match.</param>
	/// <param name="entry">When this method returns <see langword="true" />, the entry, whose members are slices of <see cref="Encoded" />.</param>
	/// <returns><see langword="true" /> if the list has an entry with the serial number; otherwise, <see langword="false" />.</returns>
	public bool TryGetEntry(ReadOnlySpan<byte> serialNumber, out RevokedCertificate entry)
	{
		if (_slots.Length is not 0 && _slots[FindSlot(serialNumber, Hash(serialNumber))] is not 0 and var slot)
		{
			entry = ReadEntry((int)(uint)slot - 1);
			return true;
		}

		entry = default;
		return false;
	}

	/// <summary>
	/// Gets the value of the authority key identifier extension (RFC 5280, Sec. 5.2.1), which identifies the key that signed the CRL.
	/// </summary>
	/// <remarks>The first call decodes the extension, and later calls return the same instance. Calls may be concurrent.</remarks>
	/// <returns>The value, or <see langword="null" /> if the CRL has no such extension.</returns>
	/// <exception cref="CryptographicException">The extension is not a DER-encoded AuthorityKeyIdentifier.</exception>
	public AuthorityKeyIdentifier? GetAuthorityKeyIdentifier()
	{
		return DecodedExtensions.AuthorityKeyIdentifier.GetValueOrThrow("authority key identifier");
	}

	/// <summary>
	/// Gets the value of the CRL number extension (RFC 5280, Sec. 5.2.3), which orders the CRLs of a scope.
	/// </summary>
	/// <remarks>The first call decodes the extension, and later calls return the same value. Calls may be concurrent.</remarks>
	/// <returns>The big-endian two's-complement contents of the INTEGER, a slice of <see cref="Encoded" />, or <see langword="null" /> if the CRL has no such extension.</returns>
	/// <exception cref="CryptographicException">The extension is not a DER-encoded INTEGER that is not negative.</exception>
	public ReadOnlyMemory<byte>? GetCrlNumber()
	{
		return DecodedExtensions.CrlNumber.GetValueOrThrow("CRL number");
	}

	/// <summary>
	/// Gets the value of the issuing distribution point extension (RFC 5280, Sec. 5.2.5), which states the scope of the CRL.
	/// </summary>
	/// <remarks>The first call decodes the extension, and later calls return the same instance. Calls may be concurrent.</remarks>
	/// <returns>The value, or <see langword="null" /> if the CRL has no such extension.</returns>
	/// <exception cref="CryptographicException">The extension is not a DER-encoded IssuingDistributionPoint, or breaks a rule of its syntax.</exception>
	public IssuingDistributionPoint? GetIssuingDistributionPoint()
	{
		return DecodedExtensions.IssuingDistributionPoint.GetValueOrThrow("issuing distribution point");
	}

	// A CRLReason ENUMERATED, in DER one byte for the values that RFC 5280, Sec. 5.3.1, defines, of which 7 is not used.
	internal static X509RevocationReason ReadReason(ReadOnlySpan<byte> contents)
	{
		return contents is [var value] && value <= 10 && value is not 7 ? (X509RevocationReason)value : throw new AsnContentException("A CRLReason has a value that is not defined.");
	}

	// encoded is owned by the new instance.
	private static CertificateRevocationList Decode(byte[] encoded, string parameterName)
	{
		try
		{
			return new CertificateRevocationList(encoded);
		}
		catch (AsnContentException e)
		{
			throw new ArgumentException("The CRL is invalid.", parameterName, e);
		}
	}

	private static int CountEntries(DerReader entries)
	{
		int count = 0;

		while (entries.HasData)
		{
			entries.ReadEncodedValue();
			++count;
		}

		return count;
	}

	// Randomized per process, so that a CRL cannot be built whose entries collide in the table. The hash takes chars, so the last byte of an odd length is mixed in separately.
	private static uint Hash(ReadOnlySpan<byte> serialNumber)
	{
		uint hash = (uint)string.GetHashCode(MemoryMarshal.Cast<byte, char>(serialNumber));

		if ((serialNumber.Length & 1) is not 0)
		{
			hash = (hash ^ serialNumber[^1]) * 0x9E3779B1;
		}

		return hash;
	}

	// revokedCertificates: SEQUENCE OF SEQUENCE { userCertificate CertificateSerialNumber, revocationDate Time, crlEntryExtensions Extensions OPTIONAL } (RFC 5280, Sec. 5.1).
	private void ReadEntries(DerReader entries)
	{
		int offset = 0;
		HashSet<string>? others = null;

		while (entries.HasData)
		{
			DerReader entry = entries.ReadSequence(out ReadOnlyMemory<byte> element);
			ReadOnlyMemory<byte> serialNumber = entry.ReadIntegerBytes();
			X509Time.Skip(ref entry);

			if (entry.HasData)
			{
				if (Version is not 2)
				{
					throw new AsnContentException();
				}

				if (!TryReadLoneReasonCode(ref entry))
				{
					CheckEntryExtensions(ref entry, ref others);
				}
			}

			entry.ThrowIfNotEmpty();
			Add(serialNumber.Span, offset);
			offset += element.Length;
		}
	}

	// The extensions of most entries that have any: one reason code extension, not critical, with a reason that Sec. 5.3.1 defines. Any others are left to CheckEntryExtensions, which decides whether they are valid.
	private static bool TryReadLoneReasonCode(ref DerReader entry)
	{
		ReadOnlySpan<byte> prefix = [0x30, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x55, 0x1D, 0x15, 0x04, 0x03, 0x0A, 0x01];
		ReadOnlySpan<byte> source = entry.GetRemaining().Span;

		if (source.Length != prefix.Length + 1 || !source.Slice(0, prefix.Length).SequenceEqual(prefix) || source[prefix.Length] > 10 || source[prefix.Length] is 7)
		{
			return false;
		}

		entry.ReadEncodedValue();
		return true;
	}

	// Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension, each extnID at most once. No string is created for the two identifiers that most entries hold; others is kept between entries so that it is created once.
	private void CheckEntryExtensions(ref DerReader entry, ref HashSet<string>? others)
	{
		const int reasonCodeBit = 1;
		const int invalidityDateBit = 2;

		ReadOnlySpan<byte> reasonCodeOid = [0x06, 0x03, 0x55, 0x1D, 0x15];
		ReadOnlySpan<byte> invalidityDateOid = [0x06, 0x03, 0x55, 0x1D, 0x18];

		DerReader sequence = entry.ReadSequence();
		sequence.ThrowIfEmpty();
		int seen = 0;
		others?.Clear();

		while (sequence.HasData)
		{
			DerReader extension = sequence.ReadSequence();
			ReadOnlySpan<byte> oid = extension.ReadEncodedValue().Span;
			bool critical = extension.ReadTrueOrAbsent();
			ReadOnlyMemory<byte> value = extension.ReadOctetString();
			extension.ThrowIfNotEmpty();

			if (oid.SequenceEqual(reasonCodeOid))
			{
				if ((seen & reasonCodeBit) is not 0)
				{
					throw new AsnContentException();
				}

				seen |= reasonCodeBit;
				ReadReasonCode(value);
			}
			else if (oid.SequenceEqual(invalidityDateOid))
			{
				if ((seen & invalidityDateBit) is not 0)
				{
					throw new AsnContentException();
				}

				seen |= invalidityDateBit;
				ReadInvalidityDate(value);
			}
			else
			{
				if (!(others ??= [with(StringComparer.Ordinal)]).Add(new ValueAsnReader(oid, AsnEncodingRules.DER).ReadObjectIdentifier()))
				{
					throw new AsnContentException();
				}

				HasUnrecognizedCriticalEntryExtension |= critical;
			}
		}
	}

	// reasonCode (RFC 5280, Sec. 5.3.1): the extnValue holds one CRLReason.
	private static X509RevocationReason ReadReasonCode(ReadOnlyMemory<byte> value)
	{
		DerReader reader = new(value);
		ReadOnlyMemory<byte> reason = reader.ReadEnumeratedBytes();
		reader.ThrowIfNotEmpty();
		return ReadReason(reason.Span);
	}

	// invalidityDate (RFC 5280, Sec. 5.3.2): the extnValue holds one GeneralizedTime.
	private static DateTimeOffset ReadInvalidityDate(ReadOnlyMemory<byte> value)
	{
		DerReader reader = new(value);
		DateTimeOffset date = X509Time.ReadGeneralizedTime(ref reader);
		reader.ThrowIfNotEmpty();
		return date;
	}

	// The position of the slot that holds the entry of serialNumber, whose hash is given, or of the free slot that ends the search for it. _slots is not empty, and half of it at least is free.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int FindSlot(ReadOnlySpan<byte> serialNumber, uint hash)
	{
		ulong[] slots = _slots;

		for (int i = (int)((ulong)hash * (uint)slots.Length >> 32); ; i = i + 1 == slots.Length ? 0 : i + 1)
		{
			ulong slot = slots[i];

			if (slot is 0 || (uint)(slot >> 32) == hash && SerialNumberAt((int)(uint)slot - 1).SequenceEqual(serialNumber))
			{
				return i;
			}
		}
	}

	// Inserts an entry whose offset in _entries is given; AsnContentException if its serial number is already in the table.
	private void Add(ReadOnlySpan<byte> serialNumber, int offset)
	{
		uint hash = Hash(serialNumber);
		ref ulong slot = ref _slots[FindSlot(serialNumber, hash)];

		if (slot is not 0)
		{
			throw new AsnContentException("The revoked certificates include a serial number more than once.");
		}

		slot = (ulong)hash << 32 | (uint)(offset + 1);
	}

	private ReadOnlySpan<byte> SerialNumberAt(int offset)
	{
		return new ValueAsnReader(_entries.Span.Slice(offset), AsnEncodingRules.DER).ReadSequence().ReadIntegerBytes();
	}

	private RevokedCertificate ReadEntry(int offset)
	{
		DerReader entries = new(_entries.Slice(offset));
		DerReader entry = entries.ReadSequence();
		ReadOnlyMemory<byte> serialNumber = entry.ReadIntegerBytes();
		DateTimeOffset revocationDate = X509Time.Read(ref entry);
		X509RevocationReason? reasonCode = null;
		DateTimeOffset? invalidityDate = null;
		IReadOnlyList<CertificateExtension> extensions = [];

		if (entry.HasData)
		{
			DerReader sequence = entry.ReadSequence();
			List<CertificateExtension> list = [];

			while (sequence.HasData)
			{
				CertificateExtension extension = CertificateExtension.Read(ref sequence);
				list.Add(extension);

				switch (extension.Oid)
				{
					case ReasonCodeOid:
					{
						reasonCode = ReadReasonCode(extension.Value);
						break;
					}
					case InvalidityDateOid:
					{
						invalidityDate = ReadInvalidityDate(extension.Value);
						break;
					}
				}
			}

			extensions = list.AsReadOnly();
		}

		return new RevokedCertificate(serialNumber, revocationDate, reasonCode, invalidityDate, extensions);
	}

	private sealed record SignatureCheck(ReadOnlyMemory<byte> PublicKeyInfo, bool Valid);
}
