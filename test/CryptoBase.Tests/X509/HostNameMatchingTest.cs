using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.X509;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.X509TestUtils;
using SubjectAlternativeName = CryptoBase.X509.SubjectAlternativeName;

namespace CryptoBase.Tests.X509;

// Host name matching as RFC 9525 specifies it, and the syntax of the host names.
public class HostNameMatchingTest
{
	private const string Label63 = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk";

	// 253 characters, the most that a DNS name without the dot of the root has.
	private const string LongestName = Label63 + "." + Label63 + "." + Label63 + "." + "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi";

	public static IEnumerable<Func<(string Case, byte[][] Names, string HostName, bool Matches)>> Rfc9525Cases()
	{
		yield return () => ("equal", [DnsName("example.com")], "example.com", true);
		yield return () => ("letters of either case", [DnsName("EXAMPLE.com")], "example.COM", true);
		yield return () => ("the dot of the root in the host name", [DnsName("example.com")], "example.com.", true);
		yield return () => ("a subdomain", [DnsName("example.com")], "www.example.com", false);
		yield return () => ("the parent", [DnsName("www.example.com")], "example.com", false);
		yield return () => ("a suffix within a label", [DnsName("example.com")], "badexample.com", false);
		yield return () => ("more labels", [DnsName("example.com")], "example.com.evil", false);
		yield return () => ("A-labels of either case", [DnsName("XN--BCHER-KVA.EXAMPLE")], "bücher.example", true);
		yield return () => ("a wildcard for one label", [DnsName("*.example.com")], "a.example.com", true);
		yield return () => ("a wildcard with letters of either case", [DnsName("*.EXAMPLE.com")], "A.example.COM.", true);
		yield return () => ("a wildcard for no label", [DnsName("*.example.com")], "example.com", false);
		yield return () => ("a wildcard for two labels", [DnsName("*.example.com")], "a.b.example.com", false);
		yield return () => ("a wildcard of another parent", [DnsName("*.example.com")], "a.example.org", false);
		yield return () => ("a wildcard before one label", [DnsName("*.example")], "a.example", true);
		yield return () => ("a wildcard for a host of one label", [DnsName("*.example")], "example", false);
		yield return () => ("a wildcard for an A-label", [DnsName("*.xn--bcher-kva.example")], "xn--caf-dma.xn--bcher-kva.example", true);
		yield return () => ("a wildcard for a U-label", [DnsName("*.xn--bcher-kva.example")], "café.bücher.example", true);
		yield return () => ("a wildcard before labels of 63 characters", [DnsName($"*.{Label63}.example")], $"{Label63}.{Label63}.example", true);
		yield return () => ("a wildcard alone", [DnsName("*")], "localhost", false);
		yield return () => ("a wildcard before an empty label", [DnsName("*.")], "a", false);
		yield return () => ("two wildcards", [DnsName("*.*.example.com")], "a.b.example.com", false);
		yield return () => ("a wildcard in the second label", [DnsName("a.*.example.com")], "a.b.example.com", false);
		yield return () => ("a wildcard ending a label", [DnsName("f*.example.com")], "foo.example.com", false);
		yield return () => ("a wildcard starting a label", [DnsName("*oo.example.com")], "foo.example.com", false);
		yield return () => ("a wildcard in an A-label", [DnsName("xn--*.example.com")], "xn--bcher-kva.example.com", false);
		yield return () => ("a double wildcard", [DnsName("**.example.com")], "a.example.com", false);
		yield return () => ("a wildcard with the dot of the root", [DnsName("*.example.com.")], "a.example.com", false);
		yield return () => ("an entry with the dot of the root", [DnsName("example.com.")], "example.com", false);
		yield return () => ("an entry with the dot of the root, and a host name with it", [DnsName("example.com.")], "example.com.", false);
		yield return () => ("an entry with an empty first label", [DnsName(".example.com")], "a.example.com", false);
		yield return () => ("an entry of a space, which RFC 5280 forbids", [DnsName(" ")], "example.com", false);
		yield return () => ("an empty entry", [DnsName("")], "example.com", false);
		yield return () => ("an entry with a NUL", [DnsName("example.com\0.evil.example")], "example.com", false);
		yield return () => ("a wildcard before a numeric last label", [DnsName("*.2.1")], "a.0.2.1.example", false);
		yield return () => ("an IP address in a dNSName", [DnsName("192.0.2.1")], "192.0.2.1", false);
		yield return () => ("an IPv4 address", [IPAddressName("192.0.2.1")], "192.0.2.1", true);
		yield return () => ("another IPv4 address", [IPAddressName("192.0.2.1")], "192.0.2.2", false);
		yield return () => ("an IPv6 address in brackets", [IPAddressName("2001:db8::1")], "[2001:DB8::1]", true);
		yield return () => ("an IPv4-mapped IPv6 address for an IPv4 address", [IPAddressName("::ffff:192.0.2.1")], "192.0.2.1", false);
		yield return () => ("an IPv4 address for an IPv4-mapped IPv6 address", [IPAddressName("192.0.2.1")], "::ffff:192.0.2.1", false);
		yield return () => ("a DNS name among IP addresses", [IPAddressName("192.0.2.1"), DnsName("example.com"), IPAddressName("2001:db8::1")], "example.com", true);
		yield return () => ("other alternatives", [Tlv(0x86, "https://example.com/"u8.ToArray()), Tlv(0x81, "user@example.com"u8.ToArray()), Tlv(0xA0, Oid("1.3.6.1.5.5.7.8.7"), Tlv(0xA0, Tlv(0x16, "_https.example.com"u8.ToArray()))), Tlv(0xA4, Name("CN=example.com"))], "example.com", false);
	}

	[Test]
	[MethodDataSource(nameof(Rfc9525Cases))]
	public async Task MatchesAsRfc9525Specifies(string @case, byte[][] names, string hostName, bool matches)
	{
		SubjectAlternativeName alternativeName = SubjectAlternativeName.Decode(GeneralNames(names));

		await Assert.That(alternativeName.MatchesHostName(hostName)).IsEqualTo(matches).Because(@case);
	}

	// Each host name and an entry that identifies it; IPAddress.Parse gives the octets of the IP addresses independently.
	public static IEnumerable<Func<(string HostName, byte[] Entry)>> ValidHostNames()
	{
		foreach (string name in (string[])["example.com", "localhost", "a", "3com.example", "123.example", "a-b.example", "a_b.example", "_a.example", "a_.example", "xn--bcher-kva.example", $"{Label63}.example", LongestName])
		{
			yield return () => (name, DnsName(name));
		}

		yield return () => ("EXAMPLE.COM.", DnsName("example.com"));
		yield return () => ($"{LongestName}.", DnsName(LongestName));

		// U-labels, among them IDN test domains of IANA.
		yield return () => ("bücher.example", DnsName("xn--bcher-kva.example"));
		yield return () => ("Bücher.EXAMPLE.", DnsName("xn--bcher-kva.example"));
		yield return () => ("faß.de", DnsName("xn--fa-hia.de"));
		yield return () => ("παράδειγμα.δοκιμή", DnsName("xn--hxajbheg2az3al.xn--jxalpdlp"));
		yield return () => ("пример.испытание", DnsName("xn--e1afmkfd.xn--80akhbyknj4f"));
		yield return () => ("例子.测试", DnsName("xn--fsqu00a.xn--0zwm56d"));
		yield return () => ("उदाहरण.परीक्षा", DnsName("xn--p1b6ci4b4b3a.xn--11b5bs3a9aj6g"));
		yield return () => ("مثال.إختبار", DnsName("xn--mgbh0fb.xn--kgbechtv"));

		// U-labels among labels in ASCII, which stay as they are, A-labels included.
		yield return () => ("例子.xn--0zwm56d", DnsName("xn--fsqu00a.xn--0zwm56d"));
		yield return () => ("xn--fsqu00a.测试", DnsName("xn--fsqu00a.xn--0zwm56d"));
		yield return () => ("XN--FSQU00A.测试.", DnsName("xn--fsqu00a.xn--0zwm56d"));
		yield return () => ("café.xn--bcher-kva.example", DnsName("xn--caf-dma.xn--bcher-kva.example"));

		foreach ((string name, string address) in ((string, string)[])[("0.0.0.0", "0.0.0.0"), ("255.255.255.255", "255.255.255.255"), ("192.0.2.1", "192.0.2.1"), ("::", "::"), ("::1", "::1"), ("[::1]", "::1"), ("1::", "1::"), ("2001:DB8::1", "2001:db8::1"), ("2001:db8:0:0:0:0:0:1", "2001:db8::1"), ("1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"), ("1:2:3:4:5:6:7::", "1:2:3:4:5:6:7:0"), ("::2:3:4:5:6:7:8", "0:2:3:4:5:6:7:8"), ("1:2:3:4:5:6:192.0.2.1", "1:2:3:4:5:6:c000:201"), ("::ffff:192.0.2.1", "::ffff:192.0.2.1"), ("::192.0.2.1", "::c000:201"), ("0000:00:0::0001", "::1")])
		{
			yield return () => (name, IPAddressName(address));
		}
	}

	[Test]
	[MethodDataSource(nameof(ValidHostNames))]
	public async Task ValidHostNamesMatchTheirEntries(string hostName, byte[] entry)
	{
		byte[][] others = [DnsName("unrelated.example"), DnsName("*.unrelated.example"), IPAddressName("198.51.100.1"), IPAddressName("2001:db8::ffff")];

		using (Assert.Multiple())
		{
			await Assert.That(SubjectAlternativeName.Decode(GeneralNames([.. others, entry])).MatchesHostName(hostName)).IsTrue().Because(hostName);
			await Assert.That(SubjectAlternativeName.Decode(GeneralNames(others)).MatchesHostName(hostName)).IsFalse().Because(hostName);
		}
	}

	// Neither DNS names nor IP addresses: names that DNS does not allow, notations of IP addresses that RFC 9525 does not recognize, and names that IDNA would map before converting them.
	public static IEnumerable<string> InvalidHostNames()
	{
		return
		[
			"", ".", "..", "a..b", ".example.com", "example.com..", "-a.example", "a-.example", "exa mple.com", "\texample.com", "example.com\0",
			"*", "*.example.com", "example.com/", "user@example.com", "example.com:443", $"{Label63}a.example", $"{LongestName}a",
			"1", "127.1", "0x7f.1", "0x7f", "0X7F", "0x", "example.123", "example.0x1f", "192.0.2.01", "0300.0.2.1", "0xC0.0.2.1", "192.0.513", "3221225985", "192.0.2.1.", "192.0.2.256", "1.2.3.4.5",
			"[192.0.2.1]", "[2001:db8::1]:443", "[2001:db8::1", "2001:db8::1]", "[]", "fe80::1%1", "fe80::1%eth0", "[fe80::1%25eth0]",
			"2001:db8::1::2", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7:8::", "12345::", ":1", "1:", ":::", "g::1", "::1.2.3.04", "1.2.3.4::", "::1.2.3", "1:2:3:4:5:6:7:192.0.2.1",

			// Upper case, an ideographic and a full-width full stop, a decomposed letter, a mark first, an emoji, a zero width joiner, a soft hyphen, a letter number, an enclosed digit, an unassigned code point, a lone surrogate and full-width digits; then a numeric last label and an underscore, which IDNA refuses.
			"BÜCHER.example", "bücher\u3002example", "bücher\uFF0Eexample", "bu\u0308cher.example", "\u0301a.example", "\U0001F600.example", "a\u200Db.example", "a\u00ADb.example", "\u2177.example", "\u2460.example", "\u0378.example", "\uD800.example", "\uFF11\uFF12\uFF17.\uFF10.\uFF10.\uFF11",
			"bücher.1", "bü_cher.example", "a_b.bücher.example",
		];
	}

	[Test]
	[MethodDataSource(nameof(InvalidHostNames))]
	public async Task InvalidHostNamesThrow(string hostName)
	{
		SubjectAlternativeName alternativeName = SubjectAlternativeName.Decode(GeneralNames(DnsName("example.com"), IPAddressName("192.0.2.1"), IPAddressName("::1")));

		await Assert.That(() => alternativeName.MatchesHostName(hostName)).Throws<ArgumentException>().WithParameterName("hostName");
	}

	// Where IdnMapping neither maps nor normalizes, as in invariant globalization mode, no name with a character that is not ASCII is in U-labels: the conversion would accept a decomposed letter, which the mapping composes, and encode it as it is.
	[Test]
	public async Task ConvertsUnicodeOnlyWhereIdnaMapsIt()
	{
		bool invariant = IsInvariantGlobalization();

		using (Assert.Multiple())
		{
			await Assert.That(HostName.ProbeIdnaMapping()).IsEqualTo(!invariant);

			foreach ((string name, string? ascii) in ((string, string?)[])[("bücher.example", "xn--bcher-kva.example"), ("例子.xn--0zwm56d", "xn--fsqu00a.xn--0zwm56d"), ("bu\u0308cher.example", null), ("xn--bcher-kva.EXAMPLE", "xn--bcher-kva.EXAMPLE"), ("a_b.example", null)])
			{
				string? withoutMapping = Ascii.IsValid(name) ? ascii : null;

				// The mapping of the platform, which invariant mode lacks.
				if (!invariant)
				{
					await Assert.That(HostName.ToAscii(name, mapsIdna: true)).IsEqualTo(ascii).Because(name);
				}

				await Assert.That(HostName.ToAscii(name, mapsIdna: false)).IsEqualTo(withoutMapping).Because(name);
				await Assert.That(HostName.ToAscii(name)).IsEqualTo(invariant ? withoutMapping : ascii).Because(name);
			}
		}

		static bool IsInvariantGlobalization()
		{
			try
			{
				return CultureInfo.GetCultureInfo("en-US").Name.Length is 0;
			}
			catch (CultureNotFoundException)
			{
				return true;
			}
		}
	}

	[Test]
	public async Task NullHostNamesThrow()
	{
		SubjectAlternativeName alternativeName = SubjectAlternativeName.Decode(GeneralNames(DnsName("example.com")));
		Certificate certificate = WithExtensions(Extension("2.5.29.17", GeneralNames(DnsName("example.com"))));

		using (Assert.Multiple())
		{
			await Assert.That(() => alternativeName.MatchesHostName(null!)).ThrowsExactly<ArgumentNullException>();
			await Assert.That(() => certificate.MatchHostName(null!)).ThrowsExactly<ArgumentNullException>();
		}
	}

	// The host names of the tests of PlatformCertificateValidator, whose results MatchHostName must give for the validator to use it.
	[Test]
	public async Task CoversTheHostNamesOfPlatformCertificateValidator()
	{
		using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		using X509Certificate2 first = BclSelfSigned(key, HashAlgorithmName.SHA256, "CN=Test Leaf", static request => request.CertificateExtensions.Add(X509TestUtils.SubjectAlternativeName("example.com", "*.example.org", "192.0.2.1")));
		using X509Certificate2 second = BclSelfSigned(key, HashAlgorithmName.SHA256, "CN=common.example", static request => request.CertificateExtensions.Add(X509TestUtils.SubjectAlternativeName("example.com", "*.example.org", "xn--bcher-kva.example")));
		using X509Certificate2 commonNameOnly = BclSelfSigned(key, HashAlgorithmName.SHA256, "CN=common.example");
		Certificate withAddress = Certificate.Decode(first.RawData);
		Certificate withIdn = Certificate.Decode(second.RawData);

		using (Assert.Multiple())
		{
			foreach (string hostName in (string[])["example.com", "EXAMPLE.com.", "a.example.org", "192.0.2.1"])
			{
				await Assert.That(withAddress.MatchHostName(hostName)).IsEqualTo(HostNameMatch.Match).Because(hostName);
			}

			await Assert.That(withIdn.MatchHostName("bücher.example")).IsEqualTo(HostNameMatch.Match);

			foreach (string hostName in (string[])["other.com", "b.a.example.org", "example.org", "common.example"])
			{
				await Assert.That(withIdn.MatchHostName(hostName)).IsEqualTo(HostNameMatch.Mismatch).Because(hostName);
			}

			await Assert.That(Certificate.Decode(commonNameOnly.RawData).MatchHostName("common.example")).IsEqualTo(HostNameMatch.Mismatch);
			await Assert.That(() => withIdn.MatchHostName("not a host")).Throws<ArgumentException>().WithParameterName("hostName");
		}
	}

	// The results of MatchHostName and of X509Certificate2.MatchesHostname without the common name on the same certificate; each group that differs names the rule.
	public static IEnumerable<Func<(string Case, byte[] Value, string HostName, string Expected, string Bcl)>> BclCases()
	{
		const string match = "Match";
		const string mismatch = "Mismatch";
		const string malformed = "Malformed";
		const string invalid = "ArgumentException";

		// The same result.
		yield return () => ("equal", GeneralNames(DnsName("example.com")), "example.com", match, match);
		yield return () => ("letters of either case and the dot of the root", GeneralNames(DnsName("example.com")), "EXAMPLE.com.", match, match);
		yield return () => ("a wildcard", GeneralNames(DnsName("*.example.com")), "a.example.com", match, match);
		yield return () => ("a wildcard for two labels", GeneralNames(DnsName("*.example.com")), "a.b.example.com", mismatch, mismatch);
		yield return () => ("a wildcard for no label", GeneralNames(DnsName("*.example.com")), "example.com", mismatch, mismatch);
		yield return () => ("a partial wildcard", GeneralNames(DnsName("f*.example.com")), "foo.example.com", mismatch, mismatch);
		yield return () => ("a wildcard alone", GeneralNames(DnsName("*")), "a", mismatch, mismatch);
		yield return () => ("a wildcard for an A-label", GeneralNames(DnsName("*.xn--bcher-kva.example")), "xn--caf-dma.xn--bcher-kva.example", match, match);
		yield return () => ("an entry with a NUL", GeneralNames(DnsName("example.com\0.evil")), "example.com", mismatch, mismatch);
		yield return () => ("an empty entry", GeneralNames(DnsName("")), "example.com", mismatch, mismatch);
		yield return () => ("an IP address in a dNSName", GeneralNames(DnsName("192.0.2.1")), "192.0.2.1", mismatch, mismatch);
		yield return () => ("an IPv4 address", GeneralNames(IPAddressName("192.0.2.1")), "192.0.2.1", match, match);
		yield return () => ("an IPv6 address in brackets", GeneralNames(IPAddressName("2001:db8::1")), "[2001:db8::1]", match, match);
		yield return () => ("an IPv4-mapped IPv6 address", GeneralNames(IPAddressName("::ffff:192.0.2.1")), "192.0.2.1", mismatch, mismatch);
		yield return () => ("a space", GeneralNames(DnsName("example.com")), "exa mple.com", invalid, invalid);
		yield return () => ("an empty label", GeneralNames(DnsName("example.com")), "a..b", invalid, invalid);
		yield return () => ("a label of 64 characters", GeneralNames(DnsName("example.com")), $"{Label63}a.example", invalid, invalid);
		yield return () => ("a port", GeneralNames(DnsName("example.com")), "example.com:443", invalid, invalid);
		yield return () => ("a dNSName that is not ASCII", GeneralNames(Tlv(0x82, [0x61, 0x80])), "example.com", malformed, malformed);
		yield return () => ("an iPAddress with a mask", GeneralNames(Tlv(0x87, [192, 0, 2, 0, 255, 255, 255, 0])), "example.com", malformed, malformed);
		yield return () => ("an unknown tag", GeneralNames(DnsName("example.com"), Tlv(0x89, [0x00])), "example.com", malformed, malformed);

		// RFC 9525, Sec. 6.3: U-labels are converted to A-labels.
		yield return () => ("a U-label", GeneralNames(DnsName("xn--bcher-kva.example")), "bücher.example", match, mismatch);

		// Notations of IPv4 addresses other than dotted decimal (RFC 3986, Sec. 3.2.2) are neither IP addresses nor DNS names (RFC 9525, Sec. 7.4).
		yield return () => ("a dotted address with two parts", GeneralNames(IPAddressName("127.0.0.1")), "127.1", invalid, match);
		yield return () => ("a dotted address of one number", GeneralNames(IPAddressName("0.0.0.1")), "1", invalid, match);
		yield return () => ("a dotted address in octal", GeneralNames(IPAddressName("192.0.2.1")), "0300.0.2.1", invalid, match);
		yield return () => ("a dotted address in hexadecimal", GeneralNames(IPAddressName("192.0.2.1")), "0xC0.0.2.1", invalid, match);
		yield return () => ("a dotted address with a leading zero", GeneralNames(IPAddressName("192.0.2.1")), "192.0.2.01", invalid, match);
		yield return () => ("an address as one number", GeneralNames(IPAddressName("192.0.2.1")), "3221225985", invalid, match);

		// A port and a zone are not part of an IP address.
		yield return () => ("an IPv6 address with a port", GeneralNames(IPAddressName("2001:db8::1")), "[2001:db8::1]:443", invalid, match);
		yield return () => ("an IPv6 address with a zone", GeneralNames(IPAddressName("fe80::1")), "fe80::1%1", invalid, mismatch);

		// A numeric last label makes neither an IP address nor a DNS name.
		yield return () => ("an IPv4 address with a trailing dot", GeneralNames(IPAddressName("192.0.2.1")), "192.0.2.1.", invalid, mismatch);
		yield return () => ("an IPv4 address beyond 255", GeneralNames(IPAddressName("192.0.2.1")), "192.0.2.256", invalid, mismatch);
		yield return () => ("a numeric top-level domain", GeneralNames(DnsName("example.123")), "example.123", invalid, match);

		// Underscores, which the preferred name syntax lacks, are allowed, as they are in names outside the Web PKI.
		yield return () => ("an underscore", GeneralNames(DnsName("a_b.example")), "a_b.example", match, match);
		yield return () => ("a wildcard with an underscore", GeneralNames(DnsName("*.a_b.example")), "c.a_b.example", match, match);

		// The preferred name syntax (RFC 5280, Sec. 4.2.1.6) has no hyphen at the end of a label, no trailing dot and at most 253 characters.
		yield return () => ("a hyphen at the end of a label", GeneralNames(DnsName("a-.example")), "a-.example", invalid, match);
		yield return () => ("an entry with the dot of the root", GeneralNames(DnsName("trailing.example.")), "trailing.example", mismatch, match);
		yield return () => ("a wildcard with the dot of the root", GeneralNames(DnsName("*.example.com.")), "a.example.com", mismatch, match);
		yield return () => ("a name of 254 characters", GeneralNames(DnsName("example.com")), $"{LongestName}a", invalid, mismatch);

		// U-labels must be in the form that IDNA keeps.
		yield return () => ("a U-label in upper case", GeneralNames(DnsName("xn--bcher-kva.example")), "BÜCHER.example", invalid, mismatch);

		// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName (RFC 5280, Sec. 4.2.1.6).
		yield return () => ("no names", GeneralNames(), "example.com", malformed, mismatch);
	}

	[Test]
	[MethodDataSource(nameof(BclCases))]
	public async Task DiffersFromTheBclOnlyWhereRfc9525Requires(string @case, byte[] value, string hostName, string expected, string bcl)
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		Certificate certificate = SelfSigned(key, SignatureAlgorithm.EcdsaSha256, "CN=example.com", new CertificateExtension("2.5.29.17", false, value));

		using (Assert.Multiple())
		{
			await Assert.That(Outcome(() => certificate.MatchHostName(hostName) switch
			{
				HostNameMatch.Match => "Match",
				HostNameMatch.Mismatch => "Mismatch",
				_ => "Malformed"
			})).IsEqualTo(expected).Because(@case);

			// Loaded without a private key, as importing one fails on macOS for an unknown GeneralName; a certificate that does not load counts as malformed.
			await Assert.That(Outcome(() =>
			{
				using X509Certificate2 platform = X509CertificateLoader.LoadCertificate(certificate.Encoded.Span);
				return platform.MatchesHostname(hostName, allowWildcards: true, allowCommonName: false) ? "Match" : "Mismatch";
			})).IsEqualTo(bcl).Because(@case);
		}

		static string Outcome(Func<string> match)
		{
			try
			{
				return match();
			}
			catch (ArgumentException)
			{
				return "ArgumentException";
			}
			catch (CryptographicException)
			{
				return "Malformed";
			}
		}
	}

	[Test]
	public async Task MatchesIPAddressesAsIPAddressParseReadsThem()
	{
		using (Assert.Multiple())
		{
			foreach (string text in (string[])["0.0.0.0", "10.20.30.40", "255.255.255.255", "::", "::1", "1::", "fe80::1:2", "2001:db8:85a3::8a2e:370:7334", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "::ffff:198.51.100.7", "1:2:3:4:5:6:7:8", "FFFF:ffff:FFFF:ffff:FFFF:ffff:255.255.255.255"])
			{
				byte[] octets = IPAddress.Parse(text).GetAddressBytes();
				SubjectAlternativeName alternativeName = SubjectAlternativeName.Decode(GeneralNames(Tlv(0x87, octets)));
				octets[^1] ^= 1;
				SubjectAlternativeName other = SubjectAlternativeName.Decode(GeneralNames(Tlv(0x87, octets)));

				await Assert.That(alternativeName.MatchesHostName(text)).IsTrue().Because(text);
				await Assert.That(other.MatchesHostName(text)).IsFalse().Because(text);
			}
		}
	}
}
