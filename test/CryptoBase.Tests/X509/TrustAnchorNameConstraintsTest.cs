using CryptoBase.Signatures.Ecdsa;
using CryptoBase.X509;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.TestPki;
using static CryptoBase.Tests.X509.TrustAnchorCertificateValidatorTest;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

// Name constraints (RFC 5280, Sec. 4.2.1.10) in TrustAnchorCertificateValidator.
public class TrustAnchorNameConstraintsTest
{
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

	// directoryName subtrees are not matched: a critical extension with one fails any path, and one that is not fails a certificate with a subject or a directoryName.
	[Test]
	public async Task RefusesDirectoryNameConstraintsThatApply()
	{
		using Authority critical = Authority.CreateRoot("CN=Critical", more: [NameConstraints([DirectoryName("O=Example")])]);
		using Authority nonCritical = Authority.CreateRoot("CN=Noncritical", more: [NameConstraints([DirectoryName("O=Example")], critical: false)]);
		Certificate leafOfCritical = critical.IssueLeaf();
		Certificate leafOfNonCritical = nonCritical.IssueLeaf();
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		Certificate withoutSubject = nonCritical.Issue(new Template { Subject = [0x30, 0x00], SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key), Extensions = [SubjectAlternativeNames(true, DnsName("example.com"))] });

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate([critical.Certificate], [leafOfCritical]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, leafOfCritical, critical.Certificate);
			await AssertInvalid(await Validate([nonCritical.Certificate], [leafOfNonCritical]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, leafOfNonCritical, nonCritical.Certificate);
			await AssertValid(await Validate([nonCritical.Certificate], [withoutSubject], hostName: "example.com"), withoutSubject, nonCritical.Certificate);
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

	// The constraints of a CA apply to the alternative names of the intermediate certificates below it too, but not to self-issued ones, as for a key rollover; and only CAs may have the extension.
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
		using Authority plain = Authority.CreateRoot("CN=Plain");
		Certificate constrainingLeaf = plain.IssueLeaf(more: [NameConstraints([DnsName("example.com")])]);

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate([root.Certificate], [leafOfOutside, outside.Certificate]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, leafOfOutside, outside.Certificate, root.Certificate);
			await AssertValid(await Validate([root.Certificate], [leafOfRollover, rollover.Certificate, inside.Certificate]), leafOfRollover, rollover.Certificate, inside.Certificate, root.Certificate);
			await AssertInvalid(await Validate([root.Certificate], [outsideLeaf, rollover.Certificate, inside.Certificate]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, outsideLeaf, rollover.Certificate, inside.Certificate, root.Certificate);
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
}
