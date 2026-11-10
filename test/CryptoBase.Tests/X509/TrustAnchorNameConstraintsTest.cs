using CryptoBase.Signatures.Ecdsa;
using CryptoBase.X509;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.TestPki;
using static CryptoBase.Tests.X509.TrustAnchorCertificateValidatorTest;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

// Name constraints (RFC 5280, Sec. 4.2.1.10) in TrustAnchorCertificateValidator.
public class TrustAnchorNameConstraintsTest
{
	private const string CommonNameType = "2.5.4.3";
	private const string DomainComponentType = "0.9.2342.19200300.100.1.25";
	private const string EmailAddressType = "1.2.840.113549.1.9.1";
	private const string UnstructuredNameType = "1.2.840.113549.1.9.2";

	public static IEnumerable<Func<(string Case, byte[][]? Permitted, byte[][]? Excluded, byte[][] Names, CertificateValidationError? Error)>> Cases()
	{
		// dNSName: the subtree with zero or more labels on the left, ignoring case; the empty subtree is every name.
		yield return () => ("DNS name equal to the subtree", [DnsName("example.com")], null, [DnsName("example.com")], null);
		yield return () => ("DNS name below the subtree", [DnsName("example.com")], null, [DnsName("www.EXAMPLE.com")], null);
		yield return () => ("DNS name that only ends with the subtree", [DnsName("example.com")], null, [DnsName("notexample.com")], CertificateValidationError.NotValidForUsage);
		yield return () => ("DNS name with the subtree in the middle", [DnsName("example.com")], null, [DnsName("example.com.evil.test")], CertificateValidationError.NotValidForUsage);
		yield return () => ("one of two DNS names outside", [DnsName("example.com")], null, [DnsName("example.com"), DnsName("example.net")], CertificateValidationError.NotValidForUsage);
		yield return () => ("excluded DNS name", null, [DnsName("example.com")], [DnsName("www.example.com")], CertificateValidationError.NotValidForUsage);
		yield return () => ("excluded beats permitted", [DnsName("example.com")], [DnsName("bad.example.com")], [DnsName("a.bad.example.com")], CertificateValidationError.NotValidForUsage);
		yield return () => ("empty excluded DNS subtree", null, [DnsName("")], [DnsName("example.com")], CertificateValidationError.NotValidForUsage);
		yield return () => ("empty excluded DNS subtree with an IP address", null, [DnsName("")], [IPAddressName("192.0.2.1")], null);
		yield return () => ("constraint of another form", [IPAddressRange("192.0.2.0/24")], null, [DnsName("example.com")], null);

		// A wildcard is permitted if every name that it stands for is, and excluded if any is.
		yield return () => ("wildcard below a permitted subtree", [DnsName("example.com")], null, [DnsName("*.example.com")], null);
		yield return () => ("wildcard wider than a permitted subtree", [DnsName("www.example.com")], null, [DnsName("*.example.com")], CertificateValidationError.NotValidForUsage);
		yield return () => ("wildcard that stands for an excluded name", [DnsName("example.com")], [DnsName("bar.example.com")], [DnsName("*.example.com")], CertificateValidationError.NotValidForUsage);
		yield return () => ("wildcard that stands for no excluded name", [DnsName("example.com")], [DnsName("a.bar.example.com")], [DnsName("*.example.com")], null);

		// iPAddress: an address and a mask, of the same family.
		yield return () => ("IPv4 address in the range", [IPAddressRange("192.0.2.0/24")], null, [IPAddressName("192.0.2.77")], null);
		yield return () => ("IPv4 address outside the range", [IPAddressRange("192.0.2.0/24")], null, [IPAddressName("192.0.3.1")], CertificateValidationError.NotValidForUsage);
		yield return () => ("IPv4 address in a range that is not on an octet", [IPAddressRange("192.0.2.128/25")], null, [IPAddressName("192.0.2.200")], null);
		yield return () => ("IPv4 address just outside a range that is not on an octet", [IPAddressRange("192.0.2.128/25")], null, [IPAddressName("192.0.2.127")], CertificateValidationError.NotValidForUsage);
		yield return () => ("IPv6 address in the range", [IPAddressRange("2001:db8::/32")], null, [IPAddressName("2001:db8:1::1")], null);
		yield return () => ("IPv4 address with an IPv6 range alone", [IPAddressRange("2001:db8::/32")], null, [IPAddressName("192.0.2.1")], CertificateValidationError.NotValidForUsage);
		yield return () => ("excluded IPv6 address", null, [IPAddressRange("2001:db8::/32")], [IPAddressName("2001:db8::1")], CertificateValidationError.NotValidForUsage);
		yield return () => ("every IPv4 address excluded", null, [IPAddressRange("0.0.0.0/0")], [IPAddressName("198.51.100.1")], CertificateValidationError.NotValidForUsage);

		// rfc822Name: a mailbox, whose local part is exact and host ignores case; a host; or a domain below a leading period.
		yield return () => ("the permitted mailbox", [Rfc822Name("root@example.com")], null, [Rfc822Name("root@EXAMPLE.com")], null);
		yield return () => ("another case of the mailbox", [Rfc822Name("root@example.com")], null, [Rfc822Name("Root@example.com")], CertificateValidationError.NotValidForUsage);
		yield return () => ("a mailbox at the permitted host", [Rfc822Name("example.com")], null, [Rfc822Name("anyone@example.com")], null);
		yield return () => ("a mailbox below the permitted host", [Rfc822Name("example.com")], null, [Rfc822Name("anyone@mail.example.com")], CertificateValidationError.NotValidForUsage);
		yield return () => ("a mailbox in the permitted domain", [Rfc822Name(".example.com")], null, [Rfc822Name("anyone@mail.example.com")], null);
		yield return () => ("a mailbox at the host of the permitted domain", [Rfc822Name(".example.com")], null, [Rfc822Name("anyone@example.com")], CertificateValidationError.NotValidForUsage);
		yield return () => ("an asterisk is literal", [Rfc822Name("*@example.com")], null, [Rfc822Name("user@example.com")], CertificateValidationError.NotValidForUsage);
		yield return () => ("an excluded mailbox", null, [Rfc822Name("bad@example.com")], [Rfc822Name("bad@example.com")], CertificateValidationError.NotValidForUsage);
		yield return () => ("an address that is not a mailbox", [Rfc822Name("example.com")], null, [Rfc822Name("bad@address@example.com")], CertificateValidationError.Malformed);

		// The forms that the validator does not match fail a name of that form, and only a name of that form.
		yield return () => ("excluded otherName and an otherName", [DnsName("example.com")], [OtherName()], [DnsName("example.com"), OtherName()], CertificateValidationError.NotValidForUsage);
		yield return () => ("excluded otherName without one", [DnsName("example.com")], [OtherName()], [DnsName("example.com")], null);
		yield return () => ("uniformResourceIdentifier subtree without a URI", [UniformResourceIdentifier(".example.com")], null, [DnsName("example.com")], null);
		yield return () => ("uniformResourceIdentifier subtree and a URI", [UniformResourceIdentifier(".example.com")], null, [DnsName("example.com"), UniformResourceIdentifier("https://www.example.com/")], CertificateValidationError.NotValidForUsage);

		// A DNS name that is not one, under a DNS subtree, cannot be checked; under subtrees of other forms it does not matter.
		yield return () => ("invalid DNS name", [DnsName("example.com")], null, [DnsName("-bad.example.com")], CertificateValidationError.Malformed);
		yield return () => ("leading period in a DNS name", [DnsName("example.com")], null, [DnsName(".example.com")], CertificateValidationError.Malformed);
		yield return () => ("invalid DNS name under an IP subtree", [IPAddressRange("192.0.2.0/24")], null, [DnsName("-bad.example.com")], null);
	}

	[Test]
	[MethodDataSource(nameof(Cases))]
	public async Task ChecksTheNamesBelowAgainstTheSubtrees(string @case, byte[][]? permitted, byte[][]? excluded, byte[][] names, CertificateValidationError? error)
	{
		using Authority root = Authority.CreateRoot(more: [NameConstraints(permitted, excluded)]);
		Certificate leaf = root.IssueLeaf(extensions: [SubjectAlternativeNames(false, names)]);

		CertificateValidationResult result = await Validate([root.Certificate], [leaf]);

		if (error is { } expected)
		{
			await AssertInvalid(result, [expected], CertificatePathEnd.TrustAnchor, @case, [leaf, root.Certificate]);
		}
		else
		{
			await AssertValid(result, leaf, root.Certificate);
		}
	}

	// The extension must keep to its syntax: DNS subtrees without a wildcard, a leading period or a trailing dot, IP subtrees of an address and a contiguous mask, mailboxes that are valid, one list at least, no list empty and no minimum or maximum.
	public static IEnumerable<Func<(string Case, byte[] Value)>> MalformedConstraints()
	{
		yield return () => ("wildcard DNS subtree", Sequence(Tlv(0xA0, Sequence(DnsName("*.example.com")))));
		yield return () => ("DNS subtree with a leading period", Sequence(Tlv(0xA0, Sequence(DnsName(".example.com")))));
		yield return () => ("DNS subtree with a trailing dot", Sequence(Tlv(0xA0, Sequence(DnsName("example.com.")))));
		yield return () => ("IP subtree without a mask", Sequence(Tlv(0xA0, Sequence(IPAddressName("192.0.2.1")))));
		yield return () => ("IP subtree with a mask that is not contiguous", Sequence(Tlv(0xA0, Sequence(Tlv(0x87, [192, 0, 2, 0, 255, 0, 255, 0])))));
		yield return () => ("IP subtree with a mask of a gap", Sequence(Tlv(0xA0, Sequence(Tlv(0x87, [192, 0, 2, 0, 255, 255, 0xF4, 0])))));
		yield return () => ("rfc822 subtree of two at signs", Sequence(Tlv(0xA0, Sequence(Rfc822Name("invalid@invalid@example.com")))));
		yield return () => ("no lists", Sequence());
		yield return () => ("an empty list", Sequence(Tlv(0xA0)));
		yield return () => ("both lists empty", Sequence(Tlv(0xA0), Tlv(0xA1)));
		yield return () => ("a minimum of zero, which DER leaves out", Sequence(Tlv(0xA0, Sequence(DnsName("example.com"), [0x80, 0x01, 0x00]))));
		yield return () => ("a maximum", Sequence(Tlv(0xA0, Sequence(DnsName("example.com"), [0x81, 0x01, 0x01]))));
		yield return () => ("an otherName subtree that is primitive", Sequence(Tlv(0xA1, Sequence([0x80, 0x01, 0x00]))));
	}

	[Test]
	[MethodDataSource(nameof(MalformedConstraints))]
	public async Task RefusesConstraintsThatAreMalformed(string @case, byte[] value)
	{
		using Authority root = Authority.CreateRoot(more: [new CertificateExtension(NameConstraintsOid, true, value)]);
		Certificate leaf = root.IssueLeaf();

		await AssertInvalid(await Validate([root.Certificate], [leaf]), [CertificateValidationError.Malformed], CertificatePathEnd.TrustAnchor, @case, [leaf, root.Certificate]);
	}

	public static IEnumerable<Func<(string Case, byte[]? Permitted, byte[]? Excluded, byte[] Subject, byte[]? AlternativeName, CertificateValidationError? Error)>> DirectoryNameCases()
	{
		byte[] example = Name("O=Example");
		byte[] other = Name("O=Other");

		yield return () => ("subject in the permitted subtree", example, null, example, null, null);
		yield return () => ("subject outside the permitted subtree", other, null, example, null, CertificateValidationError.NotValidForUsage);
		yield return () => ("subject in the excluded subtree", null, example, example, null, CertificateValidationError.NotValidForUsage);
		yield return () => ("subject outside the excluded subtree", null, other, example, null, null);
		yield return () => ("excluded beats permitted", example, example, example, null, CertificateValidationError.NotValidForUsage);
		yield return () => ("alternative name also permitted", example, null, example, example, null);
		yield return () => ("alternative name outside the permitted subtree, with the subject within it", example, null, example, other, CertificateValidationError.NotValidForUsage);
		yield return () => ("subject outside the permitted subtree, with the alternative name within it", other, null, example, other, CertificateValidationError.NotValidForUsage);
		yield return () => ("alternative name in the excluded subtree, with the subject outside it", null, example, other, example, CertificateValidationError.NotValidForUsage);
		yield return () => ("subject in the excluded subtree, with the alternative name outside it", null, example, example, other, CertificateValidationError.NotValidForUsage);
		yield return () => ("empty subject, without an alternative directory name", example, null, [0x30, 0x00], null, null);
		yield return () => ("empty subject, with an alternative directory name outside the permitted subtree", example, null, [0x30, 0x00], other, CertificateValidationError.NotValidForUsage);
	}

	// RFC 5280, Sec. 4.2.1.10: a directoryName subtree applies to a nonempty subject and to the directory names of the subject alternative name extension; an empty subject is not a directory name.
	[Test]
	[MethodDataSource(nameof(DirectoryNameCases))]
	public async Task ChecksTheDirectoryNamesAgainstTheSubtrees(string @case, byte[]? permitted, byte[]? excluded, byte[] subject, byte[]? alternativeName, CertificateValidationError? error)
	{
		using Authority root = Authority.CreateRoot(more: [NameConstraints(permitted is null ? null : [DirectoryName(permitted)], excluded is null ? null : [DirectoryName(excluded)])]);
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		Certificate leaf = root.Issue(new Template { Subject = subject, SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key), Extensions = [SubjectAlternativeNames(true, [.. alternativeName is null ? [DnsName("example.com")] : (byte[][])[DnsName("example.com"), DirectoryName(alternativeName)]]), AuthorityKeyIdentifier(root.KeyIdentifier)] });

		CertificateValidationResult result = await Validate([root.Certificate], [leaf], hostName: "example.com");

		if (error is { } expected)
		{
			await AssertInvalid(result, [expected], CertificatePathEnd.TrustAnchor, @case, [leaf, root.Certificate]);
		}
		else
		{
			await AssertValid(result, leaf, root.Certificate);
		}
	}

	public static IEnumerable<Func<(string Case, byte[]? Permitted, byte[]? Excluded, byte[] Subject, CertificateValidationError? Error, string? Message)>> UnstableNameCases()
	{
		const string might = "might be within";
		const string certain = "exclude";
		const string notPermitted = "do not permit";

		// Case folding and normalization, which the comparison does not make, could put these in the excluded subtree.
		yield return () => ("excluded, another case outside ASCII", null, Organization("É"), Organization("é"), CertificateValidationError.NotValidForUsage, might);
		yield return () => ("excluded, a full-width form", null, Organization("ＡＢＣ"), Organization("ABC"), CertificateValidationError.NotValidForUsage, might);
		yield return () => ("excluded, a decomposed form", null, Organization("\u00E9"), Organization("e\u0301"), CertificateValidationError.NotValidForUsage, might);
		yield return () => ("excluded, the subtree of ASCII and the name beyond it", null, Organization("abc"), Organization("É"), CertificateValidationError.NotValidForUsage, might);
		yield return () => ("excluded, other unstable characters between the same ends", null, Organization("Möller GmbH"), Organization("Müller GmbH"), CertificateValidationError.NotValidForUsage, might);

		// What the comparison decides exactly.
		yield return () => ("excluded, the identical name", null, Organization("é"), Organization("é"), CertificateValidationError.NotValidForUsage, certain);
		yield return () => ("excluded, different ideographs", null, Organization("北京"), Organization("上海"), null, null);
		yield return () => ("excluded, an unstable character and another end", null, Organization("Evil Corp"), Organization("Müller GmbH"), null, null);
		yield return () => ("excluded, the same ideographs", null, Organization("北京"), Organization("北京"), CertificateValidationError.NotValidForUsage, certain);
		yield return () => ("excluded, another type of attribute", null, Organization("É"), Sequence(Tlv(0x31, Sequence(Oid("2.5.4.3"), Tlv(0x0C, System.Text.Encoding.UTF8.GetBytes("é"))))), null, null);
		yield return () => ("excluded, a longer subtree", null, Sequence(Tlv(0x31, Sequence(Oid("2.5.4.10"), Tlv(0x0C, System.Text.Encoding.UTF8.GetBytes("É")))), Tlv(0x31, Sequence(Oid("2.5.4.3"), Tlv(0x13, [(byte)'x'])))), Organization("é"), null, null);

		// A permitted subtree stays exact, as a comparison that fails only leaves the name outside it.
		yield return () => ("permitted, another case outside ASCII", Organization("É"), null, Organization("é"), CertificateValidationError.NotValidForUsage, notPermitted);
		yield return () => ("permitted, the identical name", Organization("é"), null, Organization("é"), null, null);
		yield return () => ("permitted, the same ideographs", Organization("北京"), null, Organization("北京"), null, null);
		yield return () => ("permitted, different ideographs", Organization("北京"), null, Organization("上海"), CertificateValidationError.NotValidForUsage, notPermitted);

		// RFC 4518, Sec. 2.6.1, keeps a space that a combining mark follows, so that a name cannot add one to enter a permitted subtree.
		yield return () => ("permitted, a space at the start before a combining mark", Organization("\u0301a"), null, Organization(" \u0301a"), CertificateValidationError.NotValidForUsage, notPermitted);
		yield return () => ("permitted, a second space before a combining mark", Organization("x \u0301"), null, Organization("x  \u0301"), CertificateValidationError.NotValidForUsage, notPermitted);
		yield return () => ("permitted, spaces at the end after a combining mark", Organization("x\u0301"), null, Organization("x\u0301  "), null, null);
	}

	// RFC 5280, Sec. 7.1, asks for all of RFC 4518, and the comparison leaves out its case folding and normalization: a name that it could not compare exactly must not escape an excluded subtree.
	[Test]
	[MethodDataSource(nameof(UnstableNameCases))]
	public async Task FailsClosedForExcludedDirectoryNamesThatCannotBeComparedExactly(string @case, byte[]? permitted, byte[]? excluded, byte[] subject, CertificateValidationError? error, string? message)
	{
		using Authority root = Authority.CreateRoot(more: [NameConstraints(permitted is null ? null : [DirectoryName(permitted)], excluded is null ? null : [DirectoryName(excluded)])]);
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		Certificate leaf = root.Issue(new Template { Subject = subject, SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key), Extensions = [SubjectAlternativeNames("example.com"), AuthorityKeyIdentifier(root.KeyIdentifier)] });

		CertificateValidationResult result = await Validate([root.Certificate], [leaf], hostName: "example.com");

		if (error is { } expected)
		{
			using (Assert.Multiple())
			{
				await AssertInvalid(result, [expected], CertificatePathEnd.TrustAnchor, @case, [leaf, root.Certificate]);
				await Assert.That(result.Message).Contains(message ?? "").Because(@case);
			}
		}
		else
		{
			await AssertValid(result, leaf, root.Certificate);
		}
	}

	public static IEnumerable<Func<(string Case, byte[]? Permitted, byte[]? Excluded, byte[] Subject, CertificateValidationError? Error, string? Message)>> DomainComponentCases()
	{
		const byte ia5String = 0x16;
		const byte utf8String = 0x0C;
		const byte printableString = 0x13;
		const string notPermitted = "do not permit";
		const string certain = "which the name constraints of";
		const string ignored = "differs from the subtree only in characters that the preparation of RFC 4518 ignores";

		yield return () => ("permitted, the same label", DomainComponent(ia5String, "com"), null, DomainComponent(ia5String, "com"), null, null);
		yield return () => ("permitted, another case", DomainComponent(ia5String, "com"), null, DomainComponent(ia5String, "COM"), null, null);
		yield return () => ("permitted, a space at the end", DomainComponent(ia5String, "com"), null, DomainComponent(ia5String, "com "), CertificateValidationError.NotValidForUsage, notPermitted);
		yield return () => ("permitted, a space at the end in UTF8String", DomainComponent(ia5String, "com"), null, DomainComponent(utf8String, "com "), CertificateValidationError.NotValidForUsage, notPermitted);
		yield return () => ("permitted, a space among the attributes of a relative name", Dn(Rdn(Attribute(DomainComponentType, ia5String, "com"), Attribute(CommonNameType, printableString, "x"))), null, Dn(Rdn(Attribute(DomainComponentType, ia5String, "com "), Attribute(CommonNameType, printableString, "x"))), CertificateValidationError.NotValidForUsage, notPermitted);
		yield return () => ("excluded, the same label", null, DomainComponent(ia5String, "com"), DomainComponent(ia5String, "com"), CertificateValidationError.NotValidForUsage, certain);
		yield return () => ("excluded, another case in UTF8String", null, DomainComponent(ia5String, "com"), DomainComponent(utf8String, "COM"), CertificateValidationError.NotValidForUsage, certain);

		// LDAP compares the type by caseIgnoreIA5Match (RFC 4519), which ignores insignificant spaces (RFC 4517, Sec. 4.2.7), so that a label that differs only in what RFC 4518 removes must not escape an excluded subtree.
		yield return () => ("excluded, a space at the end", null, DomainComponent(ia5String, "com"), DomainComponent(ia5String, "com "), CertificateValidationError.NotValidForUsage, ignored);
		yield return () => ("excluded, a control code", null, DomainComponent(ia5String, "com"), DomainComponent(ia5String, "c\u0001om"), CertificateValidationError.NotValidForUsage, ignored);
		yield return () => ("excluded, a space among the attributes of a relative name", null, Dn(Rdn(Attribute(DomainComponentType, ia5String, "com"), Attribute(CommonNameType, printableString, "x"))), Dn(Rdn(Attribute(DomainComponentType, ia5String, "com "), Attribute(CommonNameType, printableString, "x"))), CertificateValidationError.NotValidForUsage, ignored);
		yield return () => ("excluded, a space beside a domain component outside ASCII", null, Dn(Rdn(Attribute(DomainComponentType, ia5String, "com"), Attribute(DomainComponentType, ia5String, "x"))), Dn(Rdn(Attribute(DomainComponentType, ia5String, "com "), Attribute(DomainComponentType, utf8String, "É"))), CertificateValidationError.NotValidForUsage, ignored);
		yield return () => ("excluded, a space in the last relative name", null, Dn(Rdn(Attribute(DomainComponentType, ia5String, "com")), Rdn(Attribute(DomainComponentType, ia5String, "example"))), Dn(Rdn(Attribute(DomainComponentType, ia5String, "com")), Rdn(Attribute(DomainComponentType, ia5String, "example "))), CertificateValidationError.NotValidForUsage, ignored);

		// Labels that differ in other characters stay outside the subtree.
		yield return () => ("excluded, another label", null, DomainComponent(ia5String, "com"), DomainComponent(ia5String, "org"), null, null);
		yield return () => ("excluded, a label split by a space", null, DomainComponent(ia5String, "com"), DomainComponent(ia5String, "co m"), null, null);
		yield return () => ("excluded, another label in the last relative name", null, Dn(Rdn(Attribute(DomainComponentType, ia5String, "com")), Rdn(Attribute(DomainComponentType, ia5String, "example"))), Dn(Rdn(Attribute(DomainComponentType, ia5String, "com")), Rdn(Attribute(DomainComponentType, ia5String, "examplex"))), null, null);
	}

	// RFC 5280, Sec. 7.3: domainComponent values match by a case-insensitive exact match, which a non-canonical label cannot pass to enter a permitted subtree; an excluded subtree also holds what the preparation of RFC 4518 would make equal, so that such a label cannot escape it either.
	[Test]
	[MethodDataSource(nameof(DomainComponentCases))]
	public async Task ComparesDomainComponentsByACaseInsensitiveExactMatch(string @case, byte[]? permitted, byte[]? excluded, byte[] subject, CertificateValidationError? error, string? message)
	{
		await AssertDirectoryNameSubtree(@case, permitted, excluded, subject, error, message);
	}

	// A leaf with the subject, under a root whose name constraints have the directoryName subtree, fails with the error and a message that holds the text, or is valid.
	private static async Task AssertDirectoryNameSubtree(string @case, byte[]? permitted, byte[]? excluded, byte[] subject, CertificateValidationError? error, string? message)
	{
		using Authority root = Authority.CreateRoot(more: [NameConstraints(permitted is null ? null : [DirectoryName(permitted)], excluded is null ? null : [DirectoryName(excluded)])]);
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		Certificate leaf = root.Issue(new Template { Subject = subject, SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key), Extensions = [SubjectAlternativeNames("example.com"), AuthorityKeyIdentifier(root.KeyIdentifier)] });

		CertificateValidationResult result = await Validate([root.Certificate], [leaf], hostName: "example.com");

		if (error is { } expected)
		{
			using (Assert.Multiple())
			{
				await AssertInvalid(result, [expected], CertificatePathEnd.TrustAnchor, @case, [leaf, root.Certificate]);
				await Assert.That(result.Message).Contains(message ?? "").Because(@case);
			}
		}
		else
		{
			await AssertValid(result, leaf, root.Certificate);
		}
	}

	// An identifier beyond what AsnDecoder reads does not decode, so that nothing further in a validation meets one: a CA of the peer's own, with name constraints, needs no trust anchor to reach the check of the names.
	[Test]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before the authority and the key are disposed.")]
	public async Task ANameWithAnObjectIdentifierBeyondTheLimitsOfTheBclDoesNotDecode()
	{
		using Authority attacker = Authority.CreateRoot("CN=Attacker", more: [NameConstraints([DnsName("example.com")])]);
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		byte[] subject = Sequence(Tlv(0x31, Sequence(Tlv(0x06, [.. Enumerable.Repeat((byte)0x2A, 64)]), Tlv(0x13, [(byte)'x']))), Tlv(0x31, Sequence(Oid("2.5.4.3"), Tlv(0x13, [(byte)'L']))));

		await Assert.That(() => attacker.Issue(new Template { Subject = subject, SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key) })).Throws<ArgumentException>();
	}

	// emailAddress is recognized by its identifier alone, after an identifier as long as AsnDecoder reads, and not by one that begins alike.
	[Test]
	public async Task FindsTheEmailAddressesOfTheSubjectByTheirIdentifier()
	{
		using Authority root = Authority.CreateRoot(more: [NameConstraints([Rfc822Name("example.com")])]);
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		byte[] longIdentifier = Tlv(0x31, Sequence(Tlv(0x06, [.. Enumerable.Repeat((byte)0x2A, 63)]), Tlv(0x13, [(byte)'x'])));
		byte[] outside = Sequence(longIdentifier, Tlv(0x31, Sequence(Oid("1.2.840.113549.1.9.1"), Tlv(0x16, "user@other.test"u8.ToArray()))));
		byte[] inside = Sequence(longIdentifier, Tlv(0x31, Sequence(Oid("1.2.840.113549.1.9.1"), Tlv(0x16, "user@example.com"u8.ToArray()))));
		byte[] notAnAddress = Sequence(longIdentifier, Tlv(0x31, Sequence(Oid("1.2.840.113549.1.9.10"), Tlv(0x16, "user@other.test"u8.ToArray()))));
		Certificate outsideLeaf = root.Issue(new Template { Subject = outside, SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key) });
		Certificate insideLeaf = root.Issue(new Template { Subject = inside, SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key) });
		Certificate otherLeaf = root.Issue(new Template { Subject = notAnAddress, SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key) });

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate([root.Certificate], [outsideLeaf]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, outsideLeaf, root.Certificate);
			await AssertValid(await Validate([root.Certificate], [insideLeaf]), insideLeaf, root.Certificate);
			await AssertValid(await Validate([root.Certificate], [otherLeaf]), otherLeaf, root.Certificate);
		}
	}

	// The critical or noncritical extension is processed alike, for every certificate below, the intermediate ones included; self-issued intermediate certificates are skipped, but not the peer's certificate.
	[Test]
	public async Task AppliesDirectoryNameConstraintsAsItDoesOtherConstraints()
	{
		byte[] example = Name("O=Example");
		using Authority critical = Authority.CreateRoot("CN=Critical", more: [NameConstraints([DirectoryName(example)])]);
		using Authority nonCritical = Authority.CreateRoot("CN=Noncritical", more: [NameConstraints([DirectoryName(example)], critical: false)]);
		using Authority outsideIntermediate = critical.CreateIntermediate("O=Other");
		using Authority insideIntermediate = critical.CreateIntermediate(subject: example);
		using Authority rollover = insideIntermediate.CreateIntermediate(subject: example, more: [SubjectAlternativeNames(false, DirectoryName(Name("O=Other")))]);
		Certificate leafOfRollover = rollover.IssueLeaf("O=Example");
		Certificate leafOfOutside = outsideIntermediate.IssueLeaf("O=Example");
		Certificate plain = nonCritical.IssueLeaf("CN=Outside");
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		Certificate selfIssuedLeaf = critical.Issue(new Template { Subject = critical.Name, SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key), Extensions = [SubjectAlternativeNames("example.com")] });

		using (Assert.Multiple())
		{
			await AssertValid(await Validate([critical.Certificate], [leafOfRollover, rollover.Certificate, insideIntermediate.Certificate]), leafOfRollover, rollover.Certificate, insideIntermediate.Certificate, critical.Certificate);
			await AssertInvalid(await Validate([critical.Certificate], [leafOfOutside, outsideIntermediate.Certificate]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, leafOfOutside, outsideIntermediate.Certificate, critical.Certificate);
			await AssertInvalid(await Validate([nonCritical.Certificate], [plain]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, plain, nonCritical.Certificate);
			await AssertInvalid(await Validate([critical.Certificate], [selfIssuedLeaf]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, selfIssuedLeaf, critical.Certificate);
		}
	}

	// A permitted subtree of another form says nothing about directory names, and the reverse.
	[Test]
	public async Task LeavesOtherFormsAlone()
	{
		using Authority root = Authority.CreateRoot(more: [NameConstraints([DnsName("example.com")])]);
		using Authority directory = Authority.CreateRoot("CN=Directory", more: [NameConstraints([DirectoryName(Name("O=Example"))])]);
		Certificate leaf = root.IssueLeaf("O=Whatever");
		Certificate dnsLeaf = directory.IssueLeaf("O=Example", [SubjectAlternativeNames("anything.test")]);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate([root.Certificate], [leaf]), leaf, root.Certificate);
			await AssertValid(await Validate([directory.Certificate], [dnsLeaf]), dnsLeaf, directory.Certificate);
		}
	}

	// A directoryName and a subtree count by their attributes and length, as many as 2^20 before the search stops.
	[Test]
	public async Task StopsBeforeTooManyDirectoryNameComparisons()
	{
		byte[] relativeName = Tlv(0x31, Sequence(Oid("2.5.4.3"), Tlv(0x13, [(byte)'a'])));
		byte[] under = Sequence([.. Enumerable.Repeat(relativeName, 1000)]);
		byte[] over = Sequence([.. Enumerable.Repeat(relativeName, 1100)]);
		using Authority underRoot = Authority.CreateRoot("CN=Under", more: [NameConstraints([DirectoryName(under)])]);
		using Authority overRoot = Authority.CreateRoot("CN=Over", more: [NameConstraints([DirectoryName(over)])]);
		using EcdsaP256 underKey = EcdsaP256.GenerateKey();
		using EcdsaP256 overKey = EcdsaP256.GenerateKey();
		Certificate underLeaf = underRoot.Issue(new Template { Subject = under, SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(underKey), Extensions = [SubjectAlternativeNames("example.com")] });
		Certificate overLeaf = overRoot.Issue(new Template { Subject = over, SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(overKey), Extensions = [SubjectAlternativeNames("example.com")] });

		using (Assert.Multiple())
		{
			await AssertValid(await Validate([underRoot.Certificate], [underLeaf]), underLeaf, underRoot.Certificate);
			await Assert.That((await Validate([overRoot.Certificate], [overLeaf])).Errors).Contains(CertificateValidationError.Unspecified);
		}
	}

	// RFC 5280, Sec. 4.2.1.10: without a subject alternative name extension, rfc822Name subtrees apply to the emailAddress attributes of the subject.
	[Test]
	public async Task ChecksTheEmailAddressesOfTheSubjectWithoutAlternativeNames()
	{
		using Authority root = Authority.CreateRoot(more: [NameConstraints([Rfc822Name("example.com")])]);
		Certificate inside = root.IssueLeaf("E=someone@example.com, CN=Inside", []);
		Certificate outside = root.IssueLeaf("E=someone@example.net, CN=Outside", []);
		Certificate withAlternativeNames = root.IssueLeaf("E=someone@example.net, CN=Alternative", [SubjectAlternativeNames(false, Rfc822Name("someone@example.com"))]);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate([root.Certificate], [inside], CertificateUsage.ClientAuthentication), inside, root.Certificate);
			await AssertInvalid(await Validate([root.Certificate], [outside], CertificateUsage.ClientAuthentication), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, outside, root.Certificate);
			await AssertValid(await Validate([root.Certificate], [withAlternativeNames], CertificateUsage.ClientAuthentication), withAlternativeNames, root.Certificate);
		}
	}

	// The constraints of a CA apply to the alternative names of the intermediate certificates below it too, but not to self-issued ones, as for a key rollover, whose names may match by RFC 5280, Sec. 7.1, rather than byte for byte; and only CAs may have the extension.
	[Test]
	public async Task AppliesTheConstraintsToEveryCertificateBelow()
	{
		using Authority root = Authority.CreateRoot(more: [NameConstraints([DnsName("example.com")])]);
		using Authority outside = root.CreateIntermediate(more: [SubjectAlternativeNames("other.test")]);
		Certificate leafOfOutside = outside.IssueLeaf();
		using Authority inside = root.CreateIntermediate("CN=Inside");
		using Authority rollover = inside.CreateIntermediate(subject: inside.Name, more: [SubjectAlternativeNames("other.test")]);
		Certificate leafOfRollover = rollover.IssueLeaf();
		Certificate outsideLeaf = rollover.IssueLeaf(extensions: [SubjectAlternativeNames("other.test")]);
		using Authority reencoded = inside.CreateIntermediate(subject: CommonName(Utf8StringTag, "INSIDE"), more: [SubjectAlternativeNames("other.test")]);
		Certificate leafOfReencoded = reencoded.IssueLeaf();
		using Authority plain = Authority.CreateRoot("CN=Plain");
		Certificate constrainingLeaf = plain.IssueLeaf(more: [NameConstraints([DnsName("example.com")])]);

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate([root.Certificate], [leafOfOutside, outside.Certificate]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, leafOfOutside, outside.Certificate, root.Certificate);
			await AssertValid(await Validate([root.Certificate], [leafOfRollover, rollover.Certificate, inside.Certificate]), leafOfRollover, rollover.Certificate, inside.Certificate, root.Certificate);
			await AssertInvalid(await Validate([root.Certificate], [outsideLeaf, rollover.Certificate, inside.Certificate]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, outsideLeaf, rollover.Certificate, inside.Certificate, root.Certificate);
			await AssertValid(await Validate([root.Certificate], [leafOfReencoded, reencoded.Certificate, inside.Certificate]), leafOfReencoded, reencoded.Certificate, inside.Certificate, root.Certificate);
			await AssertInvalid(await Validate([plain.Certificate], [constrainingLeaf]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, constrainingLeaf, plain.Certificate);
		}
	}

	// The subtrees of every CA of the path apply, so an intermediate certificate cannot widen what the trust anchor permits.
	[Test]
	public async Task IntersectsTheConstraintsOfThePath()
	{
		using Authority root = Authority.CreateRoot(more: [NameConstraints([DnsName("example.com")])]);
		using Authority wider = root.CreateIntermediate(more: [NameConstraints([DnsName("example.com"), DnsName("example.net")])]);
		Certificate leaf = wider.IssueLeaf(extensions: [SubjectAlternativeNames("www.example.net")]);
		Certificate inside = wider.IssueLeaf(extensions: [SubjectAlternativeNames("www.example.com")]);

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate([root.Certificate], [leaf, wider.Certificate], hostName: "www.example.net"), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, leaf, wider.Certificate, root.Certificate);
			await AssertValid(await Validate([root.Certificate], [inside, wider.Certificate], hostName: "www.example.com"), inside, wider.Certificate, root.Certificate);
		}
	}

	public static IEnumerable<Func<(string Case, byte[]? Permitted, byte[]? Excluded, byte[] Subject, CertificateValidationError? Error, string? Message)>> CaseIgnoreCases()
	{
		const byte ia5String = 0x16;
		const byte utf8String = 0x0C;
		const byte printableString = 0x13;
		const string notPermitted = "do not permit";
		const string certain = "which the name constraints of";
		const string ignored = "differs from the subtree only in characters that the preparation of RFC 4518 ignores";

		foreach ((string type, string label) in new[] { (EmailAddressType, "emailAddress"), (UnstructuredNameType, "unstructuredName") })
		{
			byte[] Value(byte tag, string value)
			{
				return Dn(Rdn(Attribute(type, tag, value)));
			}

			byte[] WithCommonName(string value)
			{
				return Dn(Rdn(Attribute(type, ia5String, value), Attribute(CommonNameType, printableString, "x")));
			}

			yield return () => ($"{label}, permitted, the same value", Value(ia5String, "a@example.com"), null, Value(ia5String, "a@example.com"), null, null);
			yield return () => ($"{label}, permitted, another case", Value(ia5String, "a@example.com"), null, Value(ia5String, "A@EXAMPLE.com"), null, null);
			yield return () => ($"{label}, permitted, a space at the end", Value(ia5String, "a@example.com"), null, Value(ia5String, "a@example.com "), CertificateValidationError.NotValidForUsage, notPermitted);
			yield return () => ($"{label}, permitted, a space among the attributes of a relative name", WithCommonName("a@example.com"), null, WithCommonName("a@example.com "), CertificateValidationError.NotValidForUsage, notPermitted);
			yield return () => ($"{label}, excluded, the same value", null, Value(ia5String, "a@example.com"), Value(ia5String, "a@example.com"), CertificateValidationError.NotValidForUsage, certain);
			yield return () => ($"{label}, excluded, another case in UTF8String", null, Value(ia5String, "a@example.com"), Value(utf8String, "A@EXAMPLE.COM"), CertificateValidationError.NotValidForUsage, certain);

			// A relying party that supports only caseIgnoreMatch, as RFC 5280, Sec. 7.1, allows, prepares the values by RFC 4518, so that one that differs only in what it removes must not escape an excluded subtree.
			yield return () => ($"{label}, excluded, a space at the end", null, Value(ia5String, "a@example.com"), Value(ia5String, "a@example.com "), CertificateValidationError.NotValidForUsage, ignored);
			yield return () => ($"{label}, excluded, a control code", null, Value(ia5String, "a@example.com"), Value(ia5String, "a@exa\u0001mple.com"), CertificateValidationError.NotValidForUsage, ignored);
			yield return () => ($"{label}, excluded, a space among the attributes of a relative name", null, WithCommonName("a@example.com"), WithCommonName("a@example.com "), CertificateValidationError.NotValidForUsage, ignored);

			// Values that differ in other characters stay outside the subtree.
			yield return () => ($"{label}, excluded, another value", null, Value(ia5String, "a@example.com"), Value(ia5String, "b@example.com"), null, null);
			yield return () => ($"{label}, excluded, a value split by a space", null, Value(ia5String, "a@example.com"), Value(ia5String, "a@exa mple.com"), null, null);
		}
	}

	// RFC 2985, Secs. 5.2.1, 5.2.2 and 6.1: emailAddress and unstructuredName values match by pkcs9CaseIgnoreMatch, which keeps every character but for case, so that a value with other white space or control codes cannot enter a permitted subtree; an excluded subtree also holds what the preparation of RFC 4518 would make equal, so that such a value cannot escape it either. The leaf has a subject alternative name, so that its emailAddress attributes are not matched as rfc822Name.
	[Test]
	[MethodDataSource(nameof(CaseIgnoreCases))]
	public async Task ComparesEmailAddressesAndUnstructuredNamesByACaseInsensitiveExactMatch(string @case, byte[]? permitted, byte[]? excluded, byte[] subject, CertificateValidationError? error, string? message)
	{
		await AssertDirectoryNameSubtree(@case, permitted, excluded, subject, error, message);
	}

	private static byte[] Organization(string value)
	{
		return Sequence(Tlv(0x31, Sequence(Oid("2.5.4.10"), Tlv(0x0C, System.Text.Encoding.UTF8.GetBytes(value)))));
	}

	private static byte[] DomainComponent(byte tag, string value)
	{
		return Dn(Rdn(Attribute(DomainComponentType, tag, value)));
	}

	private static byte[] Dn(params byte[][] relativeNames)
	{
		return Sequence(relativeNames);
	}

	// A SET OF in DER order, its elements sorted as unsigned bytes.
	private static byte[] Rdn(params byte[][] attributes)
	{
		return Tlv(0x31, [.. attributes.OrderBy(static attribute => attribute, Comparer<byte[]>.Create(static (a, b) => a.AsSpan().SequenceCompareTo(b)))]);
	}

	private static byte[] Attribute(string type, byte tag, string value)
	{
		return Sequence(Oid(type), Tlv(tag, System.Text.Encoding.UTF8.GetBytes(value)));
	}
}
