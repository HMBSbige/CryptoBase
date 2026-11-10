using CryptoBase.X509;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.X509TestUtils;
using SubjectAlternativeName = CryptoBase.X509.SubjectAlternativeName;

namespace CryptoBase.Tests.X509;

public class SubjectAlternativeNameTest
{
	[Test]
	public async Task DecodesWhatTheBclEncodes()
	{
		SubjectAlternativeNameBuilder builder = new();
		builder.AddDnsName("example.com");
		builder.AddEmailAddress("user@example.com");
		builder.AddIpAddress(IPAddress.Parse("192.0.2.1"));
		builder.AddUri(new Uri("https://example.org/path"));
		builder.AddUserPrincipalName("user@example.net");
		builder.AddDnsName("*.example.org");
		builder.AddIpAddress(IPAddress.Parse("2001:db8::1"));
		X509SubjectAlternativeNameExtension expected = new(builder.Build().RawData);

		SubjectAlternativeName decoded = SubjectAlternativeName.Decode(expected.RawData);

		using (Assert.Multiple())
		{
			await Assert.That(decoded.DnsNames).IsEquivalentTo(expected.EnumerateDnsNames(), CollectionOrdering.Matching);
			await Assert.That(decoded.IPAddresses.Select(static address => new IPAddress(address.Span).ToString())).IsEquivalentTo(expected.EnumerateIPAddresses().Select(static address => address.ToString()), CollectionOrdering.Matching);
			await Assert.That(decoded.Names.Select(static name => name.Type)).IsEquivalentTo([GeneralNameType.DnsName, GeneralNameType.Rfc822Name, GeneralNameType.IPAddress, GeneralNameType.UniformResourceIdentifier, GeneralNameType.OtherName, GeneralNameType.DnsName, GeneralNameType.IPAddress], CollectionOrdering.Matching);
			await Assert.That(System.Text.Encoding.ASCII.GetString(decoded.Names[3].Value.Span)).IsEqualTo("https://example.org/path");
		}
	}

	// Each of the nine alternatives decodes, in order, with the value that GeneralName documents.
	[Test]
	public async Task DecodesEveryAlternative()
	{
		byte[] name = Name("CN=Directory");
		byte[] value = GeneralNames(
			Tlv(0xA0, Oid("1.3.6.1.4.1.311.20.2.3"), Tlv(0xA0, [0x0C, 0x01, 0x61])),
			Tlv(0x81, "user@example.com"u8.ToArray()),
			DnsName("example.com"),
			Tlv(0xA3, Sequence()),
			Tlv(0xA4, name),
			Tlv(0xA5, Tlv(0xA0, [0x0C, 0x01, 0x61]), Tlv(0xA1, [0x0C, 0x01, 0x62])),
			Tlv(0x86, "urn:example"u8.ToArray()),
			IPAddressName("192.0.2.1"),
			[0x88, .. Oid("1.2.3.4").AsSpan(1)]);

		SubjectAlternativeName decoded = SubjectAlternativeName.Decode(value);

		using (Assert.Multiple())
		{
			await Assert.That(decoded.Names.Select(static entry => (int)entry.Type)).IsEquivalentTo(Enumerable.Range(0, 9), CollectionOrdering.Matching);
			await Assert.That(decoded.Names[4].Value.ToArray()).IsEquivalentTo(name, CollectionOrdering.Matching);
			await Assert.That(decoded.Names[7].Value.ToArray()).IsEquivalentTo((byte[])[192, 0, 2, 1], CollectionOrdering.Matching);
			await Assert.That(decoded.Names[8].Value.ToArray()).IsEquivalentTo(Oid("1.2.3.4").AsSpan(2).ToArray(), CollectionOrdering.Matching);
			await Assert.That(decoded.DnsNames).IsEquivalentTo(["example.com"], CollectionOrdering.Matching);
		}
	}

	// RFC 5280 does not forbid an entry twice, nor an empty one, whose meaning it leaves undefined; both decode.
	[Test]
	public async Task KeepsRepeatedAndEmptyEntries()
	{
		SubjectAlternativeName decoded = SubjectAlternativeName.Decode(GeneralNames(DnsName("example.com"), DnsName(""), DnsName("example.com"), IPAddressName("192.0.2.1"), IPAddressName("192.0.2.1")));

		using (Assert.Multiple())
		{
			await Assert.That(decoded.DnsNames).IsEquivalentTo(["example.com", "", "example.com"], CollectionOrdering.Matching);
			await Assert.That(decoded.IPAddresses.Count).IsEqualTo(2);
			await Assert.That(decoded.MatchesHostName("example.com")).IsTrue();
			await Assert.That(decoded.MatchesHostName("192.0.2.1")).IsTrue();
		}
	}

	public static IEnumerable<Func<(string Case, byte[] Encoding)>> MalformedCases()
	{
		byte[] valid = GeneralNames(DnsName("example.com"));

		yield return () => ("empty", []);
		yield return () => ("no names", GeneralNames());
		yield return () => ("trailing byte", [.. valid, 0x00]);
		yield return () => ("SET instead of SEQUENCE", [0x31, .. valid.AsSpan(1)]);
		yield return () => ("indefinite length", [0x30, 0x80, .. Contents(valid), 0x00, 0x00]);
		yield return () => ("length in more bytes than DER allows", WithRedundantLengthByte(valid));
		yield return () => ("truncated name", [0x30, 0x03, 0x82, 0x05, 0x61]);
		yield return () => ("universal IA5String", GeneralNames(Tlv(0x16, "example.com"u8.ToArray())));
		yield return () => ("application tag", GeneralNames(Tlv(0x42, "example.com"u8.ToArray())));
		yield return () => ("unknown tag [9]", GeneralNames(Tlv(0x89, [0x00])));
		yield return () => ("dNSName with a byte above 0x7F", GeneralNames(Tlv(0x82, [0x61, 0x80])));
		yield return () => ("constructed dNSName", GeneralNames(Tlv(0xA2, Tlv(0x16, "example.com"u8.ToArray()))));
		yield return () => ("dNSName with a redundant length byte", GeneralNames(WithRedundantLengthByte(DnsName("example.com"))));
		yield return () => ("rfc822Name with a byte above 0x7F", GeneralNames(Tlv(0x81, [0xC3, 0xA9])));
		yield return () => ("uniformResourceIdentifier with a byte above 0x7F", GeneralNames(Tlv(0x86, [0xFF])));
		yield return () => ("iPAddress of 0 octets", GeneralNames(Tlv(0x87)));
		yield return () => ("iPAddress of 5 octets", GeneralNames(Tlv(0x87, [192, 0, 2, 1, 0])));
		yield return () => ("iPAddress with a mask, as in name constraints", GeneralNames(Tlv(0x87, [192, 0, 2, 0, 255, 255, 255, 0])));
		yield return () => ("constructed iPAddress", GeneralNames(Tlv(0xA7, Tlv(0x04, [192, 0, 2, 1]))));
		yield return () => ("empty registeredID", GeneralNames(Tlv(0x88)));
		yield return () => ("registeredID with an unfinished arc", GeneralNames(Tlv(0x88, [0x2A, 0x86])));
		yield return () => ("otherName without a value", GeneralNames(Tlv(0xA0, Oid("1.2.3.4"))));
		yield return () => ("otherName with an untagged value", GeneralNames(Tlv(0xA0, Oid("1.2.3.4"), [0x05, 0x00])));
		yield return () => ("otherName with two values", GeneralNames(Tlv(0xA0, Oid("1.2.3.4"), Tlv(0xA0, [0x05, 0x00], [0x05, 0x00]))));
		yield return () => ("otherName followed by more data", GeneralNames(Tlv(0xA0, Oid("1.2.3.4"), Tlv(0xA0, [0x05, 0x00]), [0x05, 0x00])));
		yield return () => ("otherName without a type", GeneralNames(Tlv(0xA0, Tlv(0xA0, [0x05, 0x00]))));
		yield return () => ("primitive otherName", GeneralNames(Tlv(0x80, [0x05, 0x00])));
		yield return () => ("primitive x400Address", GeneralNames(Tlv(0x83)));
		yield return () => ("x400Address without built-in-standard-attributes", GeneralNames(Tlv(0xA3)));
		yield return () => ("x400Address holding a byte that is not an element", GeneralNames(Tlv(0xA3, [0xFF])));
		yield return () => ("x400Address holding a truncated element", GeneralNames(Tlv(0xA3, Sequence(), [0x30, 0x02, 0x05])));
		yield return () => ("directoryName that is not a Name", GeneralNames(Tlv(0xA4, [0x02, 0x01, 0x01])));
		yield return () => ("directoryName with an empty relative distinguished name", GeneralNames(Tlv(0xA4, Sequence(Tlv(0x31)))));
		yield return () => ("directoryName with two Names", GeneralNames(Tlv(0xA4, Name("CN=a"), Name("CN=b"))));
		yield return () => ("primitive directoryName", GeneralNames(Tlv(0x84, Name("CN=a"))));
		yield return () => ("ediPartyName without partyName", GeneralNames(Tlv(0xA5, Tlv(0xA0, [0x0C, 0x01, 0x61]))));
		yield return () => ("ediPartyName with an implicit partyName", GeneralNames(Tlv(0xA5, Tlv(0x81, [0x61]))));
		yield return () => ("ediPartyName in the wrong order", GeneralNames(Tlv(0xA5, Tlv(0xA1, [0x0C, 0x01, 0x62]), Tlv(0xA0, [0x0C, 0x01, 0x61]))));
	}

	[Test]
	[MethodDataSource(nameof(MalformedCases))]
	public async Task MalformedEncodingsThrow(string @case, byte[] encoding)
	{
		await Assert.That(() => SubjectAlternativeName.Decode(encoding)).Throws<ArgumentException>().WithParameterName("source").Because(@case);
	}

	[Test]
	public async Task DecodeCopiesItsInput()
	{
		byte[] encoding = GeneralNames(DnsName("example.com"), IPAddressName("192.0.2.1"));
		SubjectAlternativeName decoded = SubjectAlternativeName.Decode(encoding);
		Array.Clear(encoding);

		using (Assert.Multiple())
		{
			await Assert.That(decoded.DnsNames).IsEquivalentTo(["example.com"], CollectionOrdering.Matching);
			await Assert.That(decoded.IPAddresses.Single().ToArray()).IsEquivalentTo((byte[])[192, 0, 2, 1], CollectionOrdering.Matching);
		}
	}
}
