using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.X509;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.TestCrl;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

public class CertificateRevocationListTest
{
	private static TestPki.Authority CreateAuthority()
	{
		return TestPki.Authority.CreateRoot("CN=CRL Issuer");
	}

	private static Template Minimal(byte[][]? entries = null)
	{
		return new Template { Issuer = Name("CN=CRL Issuer"), Entries = entries };
	}

	private static byte[] Signed(Template template)
	{
		return template.Encode(static _ => [0x01, 0x02, 0x03]);
	}

	[Test]
	public async Task FieldsDecode()
	{
		using TestPki.Authority authority = CreateAuthority();
		DateTimeOffset thisUpdate = Now.AddHours(-1);
		DateTimeOffset nextUpdate = Now.AddDays(7);
		byte[] encoded = (Conforming(authority, [Entry([0x05], thisUpdate, ReasonCode(1)), Entry([0x7F, 0xFF], thisUpdate)]) with { ThisUpdate = Time(thisUpdate), NextUpdate = Time(nextUpdate) }).Encode(authority);

		CertificateRevocationList crl = CertificateRevocationList.Decode(encoded);

		using (Assert.Multiple())
		{
			await Assert.That(crl.Encoded.ToArray()).IsEquivalentTo(encoded, CollectionOrdering.Matching);
			await Assert.That(crl.Version).IsEqualTo(2);
			await Assert.That(crl.Issuer.ToArray()).IsEquivalentTo(authority.Name, CollectionOrdering.Matching);
			await Assert.That(crl.ThisUpdate).IsEqualTo(thisUpdate);
			await Assert.That(crl.NextUpdate).IsEqualTo(nextUpdate);
			await Assert.That(crl.RevokedCount).IsEqualTo(2);
			await Assert.That(crl.Extensions.Count).IsEqualTo(2);
			await Assert.That(crl.SignatureAlgorithm.Oid).IsEqualTo("1.2.840.10045.4.3.2");
			await Assert.That(crl.TbsCertList.Length).IsLessThan(encoded.Length);
			await Assert.That(crl.Signature.IsEmpty).IsFalse();
			await Assert.That(crl.VerifySignature(authority.Key)).IsTrue();
		}
	}

	[Test]
	public async Task VerifySignatureRejectsAnotherKeyAndAlgorithm()
	{
		using TestPki.Authority authority = CreateAuthority();
		using EcdsaP256 other = EcdsaP256.GenerateKey();
		CertificateRevocationList crl = Conforming(authority).Decode(authority);
		byte[] rsaSigned = Signed(Minimal() with { InnerSignature = Sequence(Oid("1.2.840.113549.1.1.5"), [0x05, 0x00]), OuterSignature = Sequence(Oid("1.2.840.113549.1.1.5"), [0x05, 0x00]) });

		using (Assert.Multiple())
		{
			await Assert.That(crl.VerifySignature(other)).IsFalse();
			await Assert.That(CertificateRevocationList.Decode(rsaSigned).VerifySignature(authority.Key)).IsFalse();
			await Assert.That(() => crl.VerifySignature(null!)).Throws<ArgumentNullException>();
		}
	}

	// A key that does not support the algorithm learns nothing of the signature, and so leaves no check for another key of the same SubjectPublicKeyInfo; that of a key that does is kept.
	[Test]
	public async Task KeepsNoSignatureCheckOfAKeyThatDoesNotSupportTheAlgorithm()
	{
		using TestPki.Authority authority = CreateAuthority();
		CertificateRevocationList crl = Conforming(authority).Decode(authority);
		ReadOnlyMemory<byte> publicKeyInfo = authority.Certificate.PublicKeyInfo.Encoded;
		CapabilityKey unsupporting = new(authority.Key, false);
		CapabilityKey supporting = new(authority.Key, true);

		using (Assert.Multiple())
		{
			await Assert.That(crl.VerifySignature(unsupporting, publicKeyInfo)).IsFalse();
			await Assert.That(crl.VerifySignature(supporting, publicKeyInfo)).IsTrue();
			await Assert.That(crl.VerifySignature(unsupporting, publicKeyInfo)).IsFalse();
			await Assert.That(crl.VerifySignature(supporting, publicKeyInfo)).IsTrue();
			await Assert.That(supporting.Verifications).IsEqualTo(1);
			await Assert.That(unsupporting.Verifications).IsEqualTo(0);
		}
	}

	[Test]
	public async Task EntriesAreFoundByTheContentsOfTheirIntegers()
	{
		byte[][] serials = [[0x00], [0x7F], [0x00, 0x80], [0xFF], [0x80], [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14]];
		CertificateRevocationList crl = CertificateRevocationList.Decode(Signed(Minimal([.. serials.Select(static serial => Entry(serial))])));

		using (Assert.Multiple())
		{
			await Assert.That(crl.RevokedCount).IsEqualTo(serials.Length);

			foreach (byte[] serial in serials)
			{
				await Assert.That(crl.TryGetEntry(serial, out RevokedCertificate entry)).IsTrue();
				await Assert.That(entry.SerialNumber.ToArray()).IsEquivalentTo(serial, CollectionOrdering.Matching);
			}

			// Not minimal, a different sign or a different length: none of these is a serial number of the list.
			foreach (byte[] missing in (byte[][])[[0x00, 0x7F], [0x80, 0x00], [0x7E], [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13], []])
			{
				await Assert.That(crl.TryGetEntry(missing, out RevokedCertificate entry)).IsFalse();
				await Assert.That(entry.SerialNumber.IsEmpty).IsTrue();
			}
		}
	}

	[Test]
	public async Task EntryExtensionsAreExposed()
	{
		DateTimeOffset revoked = Now.AddDays(-3);
		DateTimeOffset invalid = Now.AddDays(-5);
		byte[] invalidityDate = Extension(InvalidityDateOid, Time(invalid, generalized: true));
		byte[] other = Extension(PrivateOid, [0x05, 0x00]);
		CertificateRevocationList crl = CertificateRevocationList.Decode(Signed(Minimal([Entry([0x01], revoked, ReasonCode(1), invalidityDate, other), Entry([0x02], revoked)])));

		await Assert.That(crl.TryGetEntry((byte[])[0x01], out RevokedCertificate first)).IsTrue();
		await Assert.That(crl.TryGetEntry((byte[])[0x02], out RevokedCertificate second)).IsTrue();

		using (Assert.Multiple())
		{
			await Assert.That(first.RevocationDate).IsEqualTo(revoked);
			await Assert.That(first.ReasonCode).IsEqualTo(X509RevocationReason.KeyCompromise);
			await Assert.That(first.InvalidityDate).IsEqualTo(invalid);
			await Assert.That(first.Extensions.Select(static extension => extension.Oid)).IsEquivalentTo((string[])[ReasonCodeOid, InvalidityDateOid, PrivateOid], CollectionOrdering.Matching);
			await Assert.That(second.ReasonCode).IsNull();
			await Assert.That(second.InvalidityDate).IsNull();
			await Assert.That(second.Extensions).IsEmpty();
			await Assert.That(default(RevokedCertificate).Extensions).IsEmpty();
		}
	}

	// A list of many entries, some of which share long prefixes, finds each entry and no other, whatever the layout of the table.
	[Test]
	public async Task LargeListsFindEveryEntry()
	{
		const int count = 100_000;
		byte[][] entries = new byte[count][];

		for (int i = 0; i < count; ++i)
		{
			entries[i] = Entry(SerialNumber(i));
		}

		CertificateRevocationList crl = CertificateRevocationList.Decode(Signed(Minimal(entries)));
		int found = 0;

		for (int i = 0; i < count; ++i)
		{
			if (crl.TryGetEntry(SerialNumber(i), out RevokedCertificate entry) && entry.SerialNumber.Span.SequenceEqual(SerialNumber(i)))
			{
				++found;
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(crl.RevokedCount).IsEqualTo(count);
			await Assert.That(found).IsEqualTo(count);
			await Assert.That(crl.TryGetEntry(SerialNumber(count), out _)).IsFalse();
		}

		static byte[] SerialNumber(int i)
		{
			return [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, (byte)(i >> 24), (byte)(i >> 16), (byte)(i >> 8), (byte)i];
		}
	}

	[Test]
	public async Task RepeatedSerialNumbersAreRefused()
	{
		byte[][] adjacent = [Entry([0x01]), Entry([0x01])];
		byte[][] apart = [Entry([0x01]), Entry([0x02]), Entry([0x03]), Entry([0x01])];
		byte[][] distinct = [Entry([0x01, 0x00]), Entry([0x01]), Entry([0x7F])];

		using (Assert.Multiple())
		{
			await Assert.That(() => CertificateRevocationList.Decode(Signed(Minimal(adjacent)))).Throws<ArgumentException>();
			await Assert.That(() => CertificateRevocationList.Decode(Signed(Minimal(apart)))).Throws<ArgumentException>();
			await Assert.That(CertificateRevocationList.Decode(Signed(Minimal(distinct))).RevokedCount).IsEqualTo(3);
		}
	}

	[Test]
	public async Task VersionMustFitTheFields()
	{
		byte[] entryWithExtension = Entry([0x01], null, ReasonCode(1));
		byte[] v1 = Signed(Minimal() with { Version = null });
		byte[] v1WithEntries = Signed(Minimal([Entry([0x01])]) with { Version = null });
		byte[] v1WithEntryExtension = Signed(Minimal([entryWithExtension]) with { Version = null });
		byte[] v1WithExtensions = Signed(Minimal() with { Version = null, Extensions = [CrlNumber(1)] });
		byte[] versionZero = Signed(Minimal() with { Version = [0x02, 0x01, 0x00] });
		byte[] versionThree = Signed(Minimal() with { Version = [0x02, 0x01, 0x02] });

		using (Assert.Multiple())
		{
			await Assert.That(CertificateRevocationList.Decode(v1).Version).IsEqualTo(1);
			await Assert.That(CertificateRevocationList.Decode(v1WithEntries).RevokedCount).IsEqualTo(1);
			await Assert.That(() => CertificateRevocationList.Decode(v1WithEntryExtension)).Throws<ArgumentException>();
			await Assert.That(() => CertificateRevocationList.Decode(v1WithExtensions)).Throws<ArgumentException>();
			await Assert.That(() => CertificateRevocationList.Decode(versionZero)).Throws<ArgumentException>();
			await Assert.That(() => CertificateRevocationList.Decode(versionThree)).Throws<ArgumentException>();
		}
	}

	[Test]
	public async Task EncodingsThatAreNotDerAreRefused()
	{
		byte[] encoded = Signed(Minimal([Entry([0x01])]));
		byte[] sha384 = PartsWith(static template => template with { OuterSignature = Sequence(Oid("1.2.840.10045.4.3.3")) });
		byte[] outerAndInnerDiffer = PartsWith(static template => template with { InnerSignature = Sequence(Oid("1.2.840.10045.4.3.3")) });
		byte[] trailing = [.. encoded, 0x00];
		byte[] redundantLength = WithRedundantLengthByte(encoded);
		byte[] signatureWithUnusedBits = Sequence(Minimal().TbsCertList(), Template.EcdsaSha256, Tlv(0x03, [0x01, 0x02]));
		byte[] afterSignature = PartsWith(static template => template with { AfterSignature = [[0x05, 0x00]] });

		using (Assert.Multiple())
		{
			foreach (byte[] invalid in (byte[][])[sha384, outerAndInnerDiffer, trailing, redundantLength, signatureWithUnusedBits, afterSignature, [], [0x30, 0x00]])
			{
				await Assert.That(() => CertificateRevocationList.Decode(invalid)).Throws<ArgumentException>();
			}
		}

		static byte[] PartsWith(Func<Template, Template> change)
		{
			return change(Minimal()).Encode(static _ => [0x01]);
		}
	}

	// A list that is present but empty breaks only the rule of Sec. 5.1.2.6 for CRL issuers, and has no entries.
	[Test]
	public async Task AnEmptyListOfEntriesDecodes()
	{
		CertificateRevocationList crl = CertificateRevocationList.Decode(Signed(Minimal([])));

		using (Assert.Multiple())
		{
			await Assert.That(crl.RevokedCount).IsEqualTo(0);
			await Assert.That(crl.TryGetEntry((byte[])[0x01], out _)).IsFalse();
		}
	}

	[Test]
	public async Task ExtensionListsMustBeWellFormed()
	{
		byte[] emptyExtensions = Signed(Minimal() with { Extensions = [] });
		byte[] repeated = Signed(Minimal() with { Extensions = [CrlNumber(1), CrlNumber(2)] });
		byte[] entryEmptyExtensions = Signed(Minimal([Sequence(Tlv(0x02, [0x01]), Time(Now), Sequence())]));
		byte[] entryRepeatedKnown = Signed(Minimal([Entry([0x01], null, ReasonCode(1), ReasonCode(4))]));
		byte[] entryRepeatedOther = Signed(Minimal([Entry([0x01], null, Extension(PrivateOid, [0x05, 0x00]), Extension(PrivateOid, [0x05, 0x00]))]));
		byte[] entryExplicitNotCritical = Signed(Minimal([Entry([0x01], null, Sequence(Oid(PrivateOid), [0x01, 0x01, 0x00], Tlv(0x04, [0x05, 0x00])))]));
		byte[] entryWithExtra = Signed(Minimal([Sequence(Tlv(0x02, [0x01]), Time(Now), [0x05, 0x00])]));
		byte[] notAnEntry = Signed(Minimal([Sequence(Time(Now))]));

		using (Assert.Multiple())
		{
			foreach (byte[] invalid in (byte[][])[emptyExtensions, repeated, entryEmptyExtensions, entryRepeatedKnown, entryRepeatedOther, entryExplicitNotCritical, entryWithExtra, notAnEntry])
			{
				await Assert.That(() => CertificateRevocationList.Decode(invalid)).Throws<ArgumentException>();
			}
		}
	}

	// Sec. 5.3.1 and 5.3.2: the values that the entry extensions may hold.
	[Test]
	[Arguments((byte)7)]
	[Arguments((byte)11)]
	[Arguments((byte)0x80)]
	public async Task ReasonCodesMustBeDefined(byte reason)
	{
		await Assert.That(() => CertificateRevocationList.Decode(Signed(Minimal([Entry([0x01], null, ReasonCode(reason))])))).Throws<ArgumentException>();
	}

	[Test]
	public async Task EntryExtensionValuesMustDecode()
	{
		byte[] reasonNotEnumerated = Signed(Minimal([Entry([0x01], null, Extension(ReasonCodeOid, [0x02, 0x01, 0x01]))]));
		byte[] reasonWithExtra = Signed(Minimal([Entry([0x01], null, Extension(ReasonCodeOid, [0x0A, 0x01, 0x01, 0x00]))]));
		byte[] invalidityUtc = Signed(Minimal([Entry([0x01], null, Extension(InvalidityDateOid, Time(Now)))]));
		byte[] invalidityFraction = Signed(Minimal([Entry([0x01], null, Extension(InvalidityDateOid, Tlv(0x18, "20260101000000.5Z"u8.ToArray())))]));

		using (Assert.Multiple())
		{
			foreach (byte[] invalid in (byte[][])[reasonNotEnumerated, reasonWithExtra, invalidityUtc, invalidityFraction])
			{
				await Assert.That(() => CertificateRevocationList.Decode(invalid)).Throws<ArgumentException>();
			}
		}
	}

	[Test]
	public async Task EveryDefinedReasonDecodes()
	{
		byte[][] entries = [.. Enumerable.Range(0, 11).Where(static reason => reason is not 7).Select(static reason => Entry([(byte)(reason + 1)], null, ReasonCode((byte)reason)))];
		CertificateRevocationList crl = CertificateRevocationList.Decode(Signed(Minimal(entries)));

		using (Assert.Multiple())
		{
			foreach (int reason in Enumerable.Range(0, 11).Where(static reason => reason is not 7))
			{
				await Assert.That(crl.TryGetEntry((byte[])[(byte)(reason + 1)], out RevokedCertificate entry)).IsTrue();
				await Assert.That(entry.ReasonCode).IsEqualTo((X509RevocationReason)reason);
			}
		}
	}

	[Test]
	public async Task NextUpdateMayBeAbsent()
	{
		await Assert.That(CertificateRevocationList.Decode(Signed(Minimal() with { NextUpdate = null })).NextUpdate).IsNull();
	}

	[Test]
	public async Task TimesMayBeGeneralized()
	{
		DateTimeOffset thisUpdate = new(2050, 1, 2, 3, 4, 5, TimeSpan.Zero);
		DateTimeOffset nextUpdate = new(2051, 1, 2, 3, 4, 5, TimeSpan.Zero);
		byte[] encoded = Signed(Minimal() with { ThisUpdate = Time(thisUpdate, generalized: true), NextUpdate = Time(nextUpdate, generalized: true) });

		CertificateRevocationList crl = CertificateRevocationList.Decode(encoded);

		using (Assert.Multiple())
		{
			await Assert.That(crl.ThisUpdate).IsEqualTo(thisUpdate);
			await Assert.That(crl.NextUpdate).IsEqualTo(nextUpdate);
		}
	}

	[Test]
	public async Task ExtensionsDecodeOnFirstUse()
	{
		using TestPki.Authority authority = CreateAuthority();
		byte[] extensions = Signed(Minimal() with { Extensions = [AuthorityKeyIdentifier(authority.KeyIdentifier), CrlNumber(5)] });
		byte[] malformed = Signed(Minimal() with { Extensions = [Extension(TestCrl.AuthorityKeyIdentifierOid, [0x05, 0x00]), Extension(CrlNumberOid, [0x05, 0x00]), Extension(IssuingDistributionPointOid, [0x05, 0x00], Critical)] });
		byte[] negative = Signed(Minimal() with { Extensions = [Extension(CrlNumberOid, [0x02, 0x01, 0xFF])] });

		CertificateRevocationList good = CertificateRevocationList.Decode(extensions);
		CertificateRevocationList bad = CertificateRevocationList.Decode(malformed);

		using (Assert.Multiple())
		{
			await Assert.That(good.GetAuthorityKeyIdentifier()?.KeyIdentifier?.ToArray()).IsEquivalentTo(authority.KeyIdentifier, CollectionOrdering.Matching);
			await Assert.That(good.GetCrlNumber()?.ToArray()).IsEquivalentTo((byte[])[0x05], CollectionOrdering.Matching);
			await Assert.That(good.GetIssuingDistributionPoint()).IsNull();
			await Assert.That(() => bad.GetAuthorityKeyIdentifier()).Throws<CryptographicException>();
			await Assert.That(() => bad.GetCrlNumber()).Throws<CryptographicException>();
			await Assert.That(() => bad.GetIssuingDistributionPoint()).Throws<CryptographicException>();
			await Assert.That(() => CertificateRevocationList.Decode(negative).GetCrlNumber()).Throws<CryptographicException>();
		}
	}

	[Test]
	public async Task PemBlocksDecode()
	{
		using TestPki.Authority authority = CreateAuthority();
		string first = PemEncoding.WriteString("X509 CRL", Conforming(authority).Encode(authority));
		string second = PemEncoding.WriteString("X509 CRL", Conforming(authority, [Entry([0x01])]).Encode(authority));
		string certificate = PemEncoding.WriteString("CERTIFICATE", authority.Certificate.Encoded.Span);
		string text = $"prologue\n{certificate}\n{first}\n{second}\nepilogue";

		using (Assert.Multiple())
		{
			await Assert.That(CertificateRevocationList.DecodePem(text).RevokedCount).IsEqualTo(0);
			await Assert.That(CertificateRevocationList.DecodePemAll(text).Select(static crl => crl.RevokedCount)).IsEquivalentTo((int[])[0, 1], CollectionOrdering.Matching);
			await Assert.That(CertificateRevocationList.DecodePemAll(certificate)).IsEmpty();
			await Assert.That(() => CertificateRevocationList.DecodePem(certificate)).Throws<ArgumentException>().WithParameterName("source");
			await Assert.That(() => CertificateRevocationList.DecodePem(certificate)).Throws<ArgumentException>().WithMessageContaining("The text holds no X509 CRL block.");
			await Assert.That(() => CertificateRevocationList.DecodePem(PemEncoding.WriteString("X509 CRL", (byte[])[0x30, 0x00]))).Throws<ArgumentException>().WithParameterName("source");
			await Assert.That(() => CertificateRevocationList.DecodePemAll(PemEncoding.WriteString("X509 CRL", (byte[])[0x30, 0x00]))).Throws<ArgumentException>().WithParameterName("source");
		}
	}

	// A key whose support of the algorithms is set, as that of two implementations of the same key can differ; it counts its verifications, and leaves the inner key to its owner.
	private sealed class CapabilityKey(ISignatureKey inner, bool supports) : ISignatureKey
	{
		public int Verifications { get; private set; }

		public bool HasPrivateKey => false;

		public int SubjectPublicKeyInfoLength => inner.SubjectPublicKeyInfoLength;

		public int Pkcs8PrivateKeyLength => throw new InvalidOperationException();

		public bool Supports(SignatureAlgorithm algorithm)
		{
			return supports && inner.Supports(algorithm);
		}

		public int GetMaxSignatureLength(SignatureAlgorithm algorithm)
		{
			return inner.GetMaxSignatureLength(algorithm);
		}

		public int Sign(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, Span<byte> destination)
		{
			throw new InvalidOperationException();
		}

		public bool Verify(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
		{
			++Verifications;
			return inner.Verify(algorithm, message, signature);
		}

		public int ExportSubjectPublicKeyInfo(Span<byte> destination)
		{
			return inner.ExportSubjectPublicKeyInfo(destination);
		}

		public int ExportPkcs8PrivateKey(Span<byte> destination)
		{
			throw new InvalidOperationException();
		}

		public void Dispose()
		{
		}
	}
}
