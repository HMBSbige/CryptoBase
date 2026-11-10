using CryptoBase.X509;
using System.Text;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.X509;

public class DistinguishedNameTest
{
	private const string CommonName = "2.5.4.3";
	private const string Organization = "2.5.4.10";
	private const string Country = "2.5.4.6";
	private const string DomainComponent = "0.9.2342.19200300.100.1.25";
	private const string EmailAddress = "1.2.840.113549.1.9.1";
	private const string UnstructuredName = "1.2.840.113549.1.9.2";

	private const byte Utf8String = 0x0C;
	private const byte NumericString = 0x12;
	private const byte PrintableString = 0x13;
	private const byte TeletexString = 0x14;
	private const byte Ia5String = 0x16;
	private const byte VisibleString = 0x1A;
	private const byte UniversalString = 0x1C;
	private const byte BmpString = 0x1E;

	// The types of RFC 2985 that pkcs9CaseIgnoreMatch compares, with a name for the cases.
	private static readonly (string Type, string Label)[] CaseIgnoreTypes = [(EmailAddress, "an email address"), (UnstructuredName, "an unstructured name")];

	public static IEnumerable<Func<(string Case, byte[] Name, byte[] Subtree, bool Within)>> Cases()
	{
		yield return () => ("identical", Dn(Rdn(Attribute(CommonName, PrintableString, "Example"))), Dn(Rdn(Attribute(CommonName, PrintableString, "Example"))), true);

		// The case of ASCII letters and insignificant white space, across the string types.
		yield return () => ("another case", Dn(Rdn(Attribute(CommonName, PrintableString, "EXAMPLE"))), Dn(Rdn(Attribute(CommonName, PrintableString, "example"))), true);
		yield return () => ("spaces at the ends", Dn(Rdn(Attribute(CommonName, PrintableString, "  example  "))), Dn(Rdn(Attribute(CommonName, PrintableString, "example"))), true);
		yield return () => ("spaces inside", Dn(Rdn(Attribute(CommonName, PrintableString, "a   b   c"))), Dn(Rdn(Attribute(CommonName, PrintableString, "a b c"))), true);
		yield return () => ("a tab for a space", Dn(Rdn(Attribute(CommonName, Utf8String, "a\tb"))), Dn(Rdn(Attribute(CommonName, Utf8String, "a b"))), true);
		yield return () => ("a line feed and spaces for a space", Dn(Rdn(Attribute(CommonName, Utf8String, "a \n b"))), Dn(Rdn(Attribute(CommonName, Utf8String, "a b"))), true);
		yield return () => ("only spaces and an empty value", Dn(Rdn(Attribute(CommonName, PrintableString, "   "))), Dn(Rdn(Attribute(CommonName, PrintableString, ""))), true);
		yield return () => ("removing a space is a change", Dn(Rdn(Attribute(CommonName, PrintableString, "ab"))), Dn(Rdn(Attribute(CommonName, PrintableString, "a b"))), false);
		yield return () => ("UTF8String and PrintableString", Dn(Rdn(Attribute(CommonName, Utf8String, "Example"))), Dn(Rdn(Attribute(CommonName, PrintableString, "Example"))), true);
		yield return () => ("IA5String and PrintableString", Dn(Rdn(Attribute(CommonName, Ia5String, "Example"))), Dn(Rdn(Attribute(CommonName, PrintableString, "EXAMPLE"))), true);
		yield return () => ("VisibleString and UTF8String", Dn(Rdn(Attribute(CommonName, VisibleString, "Example"))), Dn(Rdn(Attribute(CommonName, Utf8String, "example"))), true);
		yield return () => ("PrintableString with a character outside its alphabet", Dn(Rdn(Attribute(CommonName, PrintableString, "a_b"))), Dn(Rdn(Attribute(CommonName, Utf8String, "A_B"))), true);
		yield return () => ("TeletexString, in ISO 8859-1", Dn(Rdn(AttributeOf(CommonName, TeletexString, [0xE9]))), Dn(Rdn(Attribute(CommonName, Utf8String, "é"))), true);
		yield return () => ("BMPString", Dn(Rdn(AttributeOf(CommonName, BmpString, Encoding.BigEndianUnicode.GetBytes("Cafeé")))), Dn(Rdn(Attribute(CommonName, Utf8String, "cafeé"))), true);
		yield return () => ("UniversalString", Dn(Rdn(AttributeOf(CommonName, UniversalString, Encoding.GetEncoding("utf-32BE").GetBytes("Cafe\U0001F600")))), Dn(Rdn(Attribute(CommonName, Utf8String, "cafe\U0001F600"))), true);

		// Characters that are not ASCII are compared by code point, without folding case or normalizing.
		yield return () => ("another case outside ASCII", Dn(Rdn(Attribute(CommonName, Utf8String, "É"))), Dn(Rdn(Attribute(CommonName, Utf8String, "é"))), false);
		yield return () => ("composed and decomposed", Dn(Rdn(Attribute(CommonName, Utf8String, "é"))), Dn(Rdn(Attribute(CommonName, Utf8String, "é"))), false);
		yield return () => ("a no-break space for a space", Dn(Rdn(Attribute(CommonName, Utf8String, "a\u00A0b"))), Dn(Rdn(Attribute(CommonName, Utf8String, "a b"))), true);
		yield return () => ("a next line for a space", Dn(Rdn(Attribute(CommonName, Utf8String, "a\u0085b"))), Dn(Rdn(Attribute(CommonName, Utf8String, "a b"))), true);
		yield return () => ("an ideographic space for a space", Dn(Rdn(Attribute(CommonName, Utf8String, "a\u3000b"))), Dn(Rdn(Attribute(CommonName, Utf8String, "a b"))), true);
		yield return () => ("a soft hyphen removed", Dn(Rdn(Attribute(CommonName, Utf8String, "a\u00ADb"))), Dn(Rdn(Attribute(CommonName, Utf8String, "ab"))), true);
		yield return () => ("a zero width space removed", Dn(Rdn(Attribute(CommonName, Utf8String, "a\u200Bb"))), Dn(Rdn(Attribute(CommonName, Utf8String, "ab"))), true);
		yield return () => ("a control code removed", Dn(Rdn(Attribute(CommonName, Utf8String, "a\u0001b"))), Dn(Rdn(Attribute(CommonName, Utf8String, "ab"))), true);
		yield return () => ("a variation selector removed", Dn(Rdn(Attribute(CommonName, Utf8String, "a\uFE0Fb"))), Dn(Rdn(Attribute(CommonName, Utf8String, "ab"))), true);
		yield return () => ("a tag character removed", Dn(Rdn(Attribute(CommonName, Utf8String, "a\U000E0041b"))), Dn(Rdn(Attribute(CommonName, Utf8String, "ab"))), true);
		yield return () => ("a musical format control removed", Dn(Rdn(Attribute(CommonName, Utf8String, "a\U0001D173b"))), Dn(Rdn(Attribute(CommonName, Utf8String, "ab"))), true);
		yield return () => ("another supplementary character kept", Dn(Rdn(Attribute(CommonName, Utf8String, "a\U0001D100b"))), Dn(Rdn(Attribute(CommonName, Utf8String, "ab"))), false);

		// RFC 4518, Sec. 2.6.1, keeps a space that a combining mark follows, and an unstable character could be or become one: values that differ by the spaces before one that the preparation removes are not found equal.
		yield return () => ("a space at the start before a combining mark", Dn(Rdn(Attribute(CommonName, Utf8String, " \u0301a"))), Dn(Rdn(Attribute(CommonName, Utf8String, "\u0301a"))), false);
		yield return () => ("a space at the start before a combining mark, in the subtree", Dn(Rdn(Attribute(CommonName, Utf8String, "\u0301a"))), Dn(Rdn(Attribute(CommonName, Utf8String, " \u0301a"))), false);
		yield return () => ("a second space before a combining mark", Dn(Rdn(Attribute(CommonName, Utf8String, "x  \u0301"))), Dn(Rdn(Attribute(CommonName, Utf8String, "x \u0301"))), false);
		yield return () => ("a space before a character that normalizes to a combining mark", Dn(Rdn(Attribute(CommonName, Utf8String, " \uFF9E"))), Dn(Rdn(Attribute(CommonName, Utf8String, "\uFF9E"))), false);
		yield return () => ("a space and a character removed before a combining mark", Dn(Rdn(Attribute(CommonName, Utf8String, " \u200B\u0301a"))), Dn(Rdn(Attribute(CommonName, Utf8String, "\u0301a"))), false);
		yield return () => ("identical spaces before a combining mark", Dn(Rdn(Attribute(CommonName, Utf8String, " \u0301a"))), Dn(Rdn(Attribute(CommonName, Utf8String, " \u0301a"))), true);
		yield return () => ("one space before a combining mark, in another string type", Dn(Rdn(AttributeOf(CommonName, BmpString, Encoding.BigEndianUnicode.GetBytes("x \u0301")))), Dn(Rdn(Attribute(CommonName, Utf8String, "x\u00A0\u0301"))), true);
		yield return () => ("spaces at the end after a combining mark", Dn(Rdn(Attribute(CommonName, Utf8String, "x\u0301  "))), Dn(Rdn(Attribute(CommonName, Utf8String, "x\u0301"))), true);
		yield return () => ("spaces before a stable character after a combining mark", Dn(Rdn(Attribute(CommonName, Utf8String, "x\u0301   y"))), Dn(Rdn(Attribute(CommonName, Utf8String, "x\u0301 y"))), true);

		// Other types and values that do not decode compare byte for byte.
		yield return () => ("NumericString identical", Dn(Rdn(Attribute(CommonName, NumericString, "123"))), Dn(Rdn(Attribute(CommonName, NumericString, "123"))), true);
		yield return () => ("NumericString against PrintableString", Dn(Rdn(Attribute(CommonName, NumericString, "123"))), Dn(Rdn(Attribute(CommonName, PrintableString, "123"))), false);
		yield return () => ("OCTET STRING with another case", Dn(Rdn(Attribute(CommonName, 0x04, "aB"))), Dn(Rdn(Attribute(CommonName, 0x04, "Ab"))), false);
		yield return () => ("invalid UTF-8, identical", Dn(Rdn(AttributeOf(CommonName, Utf8String, [0xFF]))), Dn(Rdn(AttributeOf(CommonName, Utf8String, [0xFF]))), true);
		yield return () => ("invalid UTF-8, another case of the rest", Dn(Rdn(AttributeOf(CommonName, Utf8String, [(byte)'a', 0xFF]))), Dn(Rdn(AttributeOf(CommonName, Utf8String, [(byte)'A', 0xFF]))), false);
		yield return () => ("a BMPString of an odd length", Dn(Rdn(AttributeOf(CommonName, BmpString, [0x00]))), Dn(Rdn(AttributeOf(CommonName, BmpString, [0x00]))), true);
		yield return () => ("a UniversalString that is not valid, against text", Dn(Rdn(AttributeOf(CommonName, UniversalString, [0x7F, 0xFF, 0xFF, 0xFF]))), Dn(Rdn(Attribute(CommonName, Utf8String, ""))), false);

		// RFC 5280, Sec. 7.3: domainComponent values match by a case-insensitive exact match, without the preparation of RFC 4518, in whatever string type they come.
		yield return () => ("a domain component of another case", Dn(Rdn(Attribute(DomainComponent, Ia5String, "Example"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "eXAMPLE"))), true);
		yield return () => ("a domain component with a space at the end", Dn(Rdn(Attribute(DomainComponent, Ia5String, "com "))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"))), false);
		yield return () => ("a domain component with a space at the start", Dn(Rdn(Attribute(DomainComponent, Ia5String, " com"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"))), false);
		yield return () => ("a domain component with a space at the end, in the subtree", Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "com "))), false);
		yield return () => ("a domain component with spaces inside", Dn(Rdn(Attribute(DomainComponent, Ia5String, "a  b"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "a b"))), false);
		yield return () => ("a domain component with a tab for a space", Dn(Rdn(Attribute(DomainComponent, Ia5String, "a	b"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "a b"))), false);
		yield return () => ("a domain component with a control code", Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"))), false);
		yield return () => ("a domain component with a soft hyphen", Dn(Rdn(Attribute(DomainComponent, Utf8String, "c­om"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"))), false);
		yield return () => ("identical domain components with a space", Dn(Rdn(Attribute(DomainComponent, Ia5String, "com "))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "COM "))), true);
		yield return () => ("a domain component in UTF8String", Dn(Rdn(Attribute(DomainComponent, Utf8String, "COM"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"))), true);
		yield return () => ("a domain component in PrintableString with a space", Dn(Rdn(Attribute(DomainComponent, PrintableString, " com"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"))), false);
		yield return () => ("a domain component of another case outside ASCII", Dn(Rdn(Attribute(DomainComponent, Utf8String, "É"))), Dn(Rdn(Attribute(DomainComponent, Utf8String, "é"))), false);
		yield return () => ("a domain component with a space, among other attributes", Dn(Rdn(Attribute(DomainComponent, Ia5String, "com "), Attribute(CommonName, PrintableString, "x"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"), Attribute(CommonName, PrintableString, "x"))), false);
		yield return () => ("a domain component and another attribute with a space", Dn(Rdn(Attribute(DomainComponent, Ia5String, "COM"), Attribute(CommonName, PrintableString, "x "))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"), Attribute(CommonName, PrintableString, "x"))), true);

		// RFC 2985, Secs. 5.2.1, 5.2.2 and 6.1: emailAddress and unstructuredName values match by pkcs9CaseIgnoreMatch, the same characters but for case, without the preparation of RFC 4518, in whatever string type they come.
		foreach ((string type, string label) in CaseIgnoreTypes)
		{
			yield return () => ($"{label} of another case", Dn(Rdn(Attribute(type, Ia5String, "A@Example.com"))), Dn(Rdn(Attribute(type, Ia5String, "a@eXAMPLE.COM"))), true);
			yield return () => ($"{label} with a space at the end", Dn(Rdn(Attribute(type, Ia5String, "a@example.com "))), Dn(Rdn(Attribute(type, Ia5String, "a@example.com"))), false);
			yield return () => ($"{label} with a space at the start", Dn(Rdn(Attribute(type, Ia5String, " a@example.com"))), Dn(Rdn(Attribute(type, Ia5String, "a@example.com"))), false);
			yield return () => ($"{label} with a space at the end, in the subtree", Dn(Rdn(Attribute(type, Ia5String, "a@example.com"))), Dn(Rdn(Attribute(type, Ia5String, "a@example.com "))), false);
			yield return () => ($"{label} with spaces inside", Dn(Rdn(Attribute(type, Ia5String, "a  b"))), Dn(Rdn(Attribute(type, Ia5String, "a b"))), false);
			yield return () => ($"{label} with a tab for a space", Dn(Rdn(Attribute(type, Ia5String, "a\tb"))), Dn(Rdn(Attribute(type, Ia5String, "a b"))), false);
			yield return () => ($"{label} with a control code", Dn(Rdn(Attribute(type, Ia5String, "a@exa\u0001mple.com"))), Dn(Rdn(Attribute(type, Ia5String, "a@example.com"))), false);
			yield return () => ($"{label} with a soft hyphen", Dn(Rdn(Attribute(type, Utf8String, "a@exa\u00ADmple.com"))), Dn(Rdn(Attribute(type, Ia5String, "a@example.com"))), false);
			yield return () => ($"identical {label}s with a space", Dn(Rdn(Attribute(type, Ia5String, "a@example.com "))), Dn(Rdn(Attribute(type, Ia5String, "A@EXAMPLE.COM "))), true);
			yield return () => ($"{label} in UTF8String", Dn(Rdn(Attribute(type, Utf8String, "A@EXAMPLE.COM"))), Dn(Rdn(Attribute(type, Ia5String, "a@example.com"))), true);
			yield return () => ($"{label} in BMPString", Dn(Rdn(AttributeOf(type, BmpString, Encoding.BigEndianUnicode.GetBytes("A@Example.com")))), Dn(Rdn(Attribute(type, Ia5String, "a@example.com"))), true);
			yield return () => ($"{label} in BMPString with a space", Dn(Rdn(AttributeOf(type, BmpString, Encoding.BigEndianUnicode.GetBytes("a@example.com ")))), Dn(Rdn(Attribute(type, Ia5String, "a@example.com"))), false);
			yield return () => ($"{label} of another case outside ASCII", Dn(Rdn(Attribute(type, Utf8String, "É"))), Dn(Rdn(Attribute(type, Utf8String, "é"))), false);
			yield return () => ($"{label} with a space, among other attributes", Dn(Rdn(Attribute(type, Ia5String, "a@example.com "), Attribute(CommonName, PrintableString, "x"))), Dn(Rdn(Attribute(type, Ia5String, "a@example.com"), Attribute(CommonName, PrintableString, "x"))), false);
			yield return () => ($"{label} and another attribute with a space", Dn(Rdn(Attribute(type, Ia5String, "A@EXAMPLE.COM"), Attribute(CommonName, PrintableString, "x "))), Dn(Rdn(Attribute(type, Ia5String, "a@example.com"), Attribute(CommonName, PrintableString, "x"))), true);
		}

		// Types must be the same, and the subtree is a prefix of relative names, in order.
		yield return () => ("another type of attribute", Dn(Rdn(Attribute(Organization, PrintableString, "a"))), Dn(Rdn(Attribute(CommonName, PrintableString, "a"))), false);
		yield return () => ("a longer name in the subtree", Dn(Rdn(Attribute(Country, PrintableString, "US")), Rdn(Attribute(CommonName, PrintableString, "x"))), Dn(Rdn(Attribute(Country, PrintableString, "US"))), true);
		yield return () => ("a shorter name", Dn(Rdn(Attribute(Country, PrintableString, "US"))), Dn(Rdn(Attribute(Country, PrintableString, "US")), Rdn(Attribute(CommonName, PrintableString, "x"))), false);
		yield return () => ("another order", Dn(Rdn(Attribute(CommonName, PrintableString, "x")), Rdn(Attribute(Country, PrintableString, "US"))), Dn(Rdn(Attribute(Country, PrintableString, "US")), Rdn(Attribute(CommonName, PrintableString, "x"))), false);
		yield return () => ("a suffix does not match", Dn(Rdn(Attribute(Country, PrintableString, "US")), Rdn(Attribute(CommonName, PrintableString, "x"))), Dn(Rdn(Attribute(CommonName, PrintableString, "x"))), false);
		yield return () => ("the empty name as the subtree of every name", Dn(Rdn(Attribute(CommonName, PrintableString, "x"))), Dn(), true);
		yield return () => ("the empty name within itself", Dn(), Dn(), true);
		yield return () => ("the empty name within another", Dn(), Dn(Rdn(Attribute(CommonName, PrintableString, "x"))), false);

		// Relative names with more than one attribute compare as sets of the same size, in whatever order the case makes DER sort them.
		yield return () => ("two attributes", Dn(Rdn(Attribute(CommonName, PrintableString, "a"), Attribute(Organization, PrintableString, "b"))), Dn(Rdn(Attribute(Organization, PrintableString, "b"), Attribute(CommonName, PrintableString, "a"))), true);
		yield return () => ("two attributes, another case", Dn(Rdn(Attribute(CommonName, PrintableString, "A"), Attribute(CommonName, Utf8String, "b"))), Dn(Rdn(Attribute(CommonName, PrintableString, "B"), Attribute(CommonName, Utf8String, "a"))), true);
		yield return () => ("more attributes in the name", Dn(Rdn(Attribute(CommonName, PrintableString, "a"), Attribute(Organization, PrintableString, "b"))), Dn(Rdn(Attribute(CommonName, PrintableString, "a"))), false);
		yield return () => ("more attributes in the subtree", Dn(Rdn(Attribute(CommonName, PrintableString, "a"))), Dn(Rdn(Attribute(CommonName, PrintableString, "a"), Attribute(Organization, PrintableString, "b"))), false);
		yield return () => ("an attribute appearing twice is no match for two different ones", Dn(Rdn(Attribute(CommonName, PrintableString, "a"), Attribute(CommonName, Utf8String, "a"))), Dn(Rdn(Attribute(CommonName, PrintableString, "a"), Attribute(Organization, PrintableString, "b"))), false);
		yield return () => ("attribute value mismatch", Dn(Rdn(Attribute(CommonName, PrintableString, "a"), Attribute(Organization, PrintableString, "b"))), Dn(Rdn(Attribute(CommonName, PrintableString, "a"), Attribute(Organization, PrintableString, "c"))), false);
		yield return () => ("many attributes", Dn(Rdn([.. Enumerable.Range(0, 80).Select(static i => Attribute(CommonName, PrintableString, $"v{i}"))])), Dn(Rdn([.. Enumerable.Range(0, 80).Reverse().Select(static i => Attribute(CommonName, PrintableString, $"V{i}"))])), true);
	}

	[Test]
	[MethodDataSource(nameof(Cases))]
	public async Task ComparesNamesAsRfc5280Requires(string @case, byte[] name, byte[] subtree, bool within)
	{
		DistinguishedName parsedName = DistinguishedName.Read(name);
		DistinguishedName parsedSubtree = DistinguishedName.Read(subtree);

		await Assert.That(parsedName.IsWithin(parsedSubtree)).IsEqualTo(within).Because(@case);
	}

	public static IEnumerable<Func<(string Case, byte[] Name, byte[] Subtree, bool MightBeWithin)>> UnstableCases()
	{
		// What a complete comparison, with the case folding and normalization of RFC 4518, could find equal.
		yield return () => ("another case outside ASCII", Dn(Rdn(Attribute(Organization, Utf8String, "É"))), Dn(Rdn(Attribute(Organization, Utf8String, "é"))), true);
		yield return () => ("composed and decomposed", Dn(Rdn(Attribute(Organization, Utf8String, "\u00E9"))), Dn(Rdn(Attribute(Organization, Utf8String, "e\u0301"))), true);
		yield return () => ("a full-width form", Dn(Rdn(Attribute(Organization, Utf8String, "ＡＢＣ"))), Dn(Rdn(Attribute(Organization, Utf8String, "ABC"))), true);
		yield return () => ("a ligature", Dn(Rdn(Attribute(Organization, Utf8String, "ﬁ"))), Dn(Rdn(Attribute(Organization, Utf8String, "fi"))), true);
		yield return () => ("a character of a supplementary plane", Dn(Rdn(Attribute(Organization, Utf8String, "\U0001D400"))), Dn(Rdn(Attribute(Organization, Utf8String, "A"))), true);
		yield return () => ("the unstable text in the subtree", Dn(Rdn(Attribute(Organization, Utf8String, "abc"))), Dn(Rdn(Attribute(Organization, Utf8String, "É"))), true);

		// What the comparison decides as it is: identical names, and the characters that the folding and normalization do not change.
		yield return () => ("names of ASCII that differ", Dn(Rdn(Attribute(Organization, Utf8String, "abc"))), Dn(Rdn(Attribute(Organization, Utf8String, "abd"))), false);
		yield return () => ("another case of ASCII", Dn(Rdn(Attribute(Organization, Utf8String, "ABC"))), Dn(Rdn(Attribute(Organization, Utf8String, "abc"))), true);
		yield return () => ("different ideographs", Dn(Rdn(Attribute(Organization, Utf8String, "北京"))), Dn(Rdn(Attribute(Organization, Utf8String, "上海"))), false);
		yield return () => ("identical ideographs", Dn(Rdn(Attribute(Organization, Utf8String, "北京"))), Dn(Rdn(Attribute(Organization, Utf8String, "北京"))), true);
		yield return () => ("ideographs of extension A", Dn(Rdn(Attribute(Organization, Utf8String, "\u3400"))), Dn(Rdn(Attribute(Organization, Utf8String, "\u4DBF"))), false);
		yield return () => ("Hangul syllables that differ", Dn(Rdn(Attribute(Organization, Utf8String, "서울"))), Dn(Rdn(Attribute(Organization, Utf8String, "부산"))), false);
		yield return () => ("hiragana and katakana that differ", Dn(Rdn(Attribute(Organization, Utf8String, "あ"))), Dn(Rdn(Attribute(Organization, Utf8String, "ア"))), false);
		yield return () => ("katakana with the long sound mark, the middle dot and the iteration marks", Dn(Rdn(Attribute(Organization, Utf8String, "コーヒー・ヽヾゝゞ"))), Dn(Rdn(Attribute(Organization, Utf8String, "サーバー"))), false);
		yield return () => ("just after the katakana", Dn(Rdn(Attribute(Organization, Utf8String, "\u30FF"))), Dn(Rdn(Attribute(Organization, Utf8String, "abc"))), true);
		yield return () => ("just before the ideographs", Dn(Rdn(Attribute(Organization, Utf8String, "\u33FF"))), Dn(Rdn(Attribute(Organization, Utf8String, "abc"))), true);
		yield return () => ("just after the ideographs", Dn(Rdn(Attribute(Organization, Utf8String, "\uA000"))), Dn(Rdn(Attribute(Organization, Utf8String, "abc"))), true);
		yield return () => ("just after the syllables", Dn(Rdn(Attribute(Organization, Utf8String, "\uD7A4"))), Dn(Rdn(Attribute(Organization, Utf8String, "abc"))), true);
		yield return () => ("a compatibility ideograph", Dn(Rdn(Attribute(Organization, Utf8String, "\uF900"))), Dn(Rdn(Attribute(Organization, Utf8String, "\u8C48"))), true);
		yield return () => ("a half-width katakana", Dn(Rdn(Attribute(Organization, Utf8String, "\uFF76"))), Dn(Rdn(Attribute(Organization, Utf8String, "\u30AB"))), true);
		yield return () => ("a character prepared away", Dn(Rdn(Attribute(Organization, Utf8String, "a\u00ADb"))), Dn(Rdn(Attribute(Organization, Utf8String, "ac"))), false);

		// An unstable character could become anything, but the characters out of its reach must be the same, from each end up to the first that it could change.
		yield return () => ("an unstable character and another end", Dn(Rdn(Attribute(Organization, Utf8String, "M\u00FCller GmbH"))), Dn(Rdn(Attribute(Organization, Utf8String, "Evil Corp"))), false);
		yield return () => ("another start before an unstable character", Dn(Rdn(Attribute(Organization, Utf8String, "ab\u00FCx"))), Dn(Rdn(Attribute(Organization, Utf8String, "cd\u00FCx"))), false);
		yield return () => ("another end after an unstable character", Dn(Rdn(Attribute(Organization, Utf8String, "x\u00FCbc"))), Dn(Rdn(Attribute(Organization, Utf8String, "x\u00FCde"))), false);
		yield return () => ("another start of the shorter text, from the end", Dn(Rdn(Attribute(Organization, Utf8String, "\u0301abc"))), Dn(Rdn(Attribute(Organization, Utf8String, "xbc"))), false);
		yield return () => ("the unstable characters differ and the ends are the same", Dn(Rdn(Attribute(Organization, Utf8String, "M\u00FCller GmbH"))), Dn(Rdn(Attribute(Organization, Utf8String, "M\u00F6ller GmbH"))), true);
		yield return () => ("no character out of reach", Dn(Rdn(Attribute(Organization, Utf8String, "\u0418\u0432\u0430\u043D\u043E\u0432"))), Dn(Rdn(Attribute(Organization, Utf8String, "\u041F\u0435\u0442\u0440\u043E\u0432"))), true);

		// Pairs that RFC 4518 makes equal. A character before an unstable one could compose with it, though both sides have stable characters there.
		yield return () => ("a combining mark composes a kana", Dn(Rdn(Attribute(Organization, Utf8String, "\u304B\u3099"))), Dn(Rdn(Attribute(Organization, Utf8String, "\u304C"))), true);
		yield return () => ("a jamo composes a syllable", Dn(Rdn(Attribute(Organization, Utf8String, "\uAC00\u11A8"))), Dn(Rdn(Attribute(Organization, Utf8String, "\uAC01"))), true);
		yield return () => ("a jamo composes a syllable of the name", Dn(Rdn(Attribute(Organization, Utf8String, "\uAC01"))), Dn(Rdn(Attribute(Organization, Utf8String, "\uAC00\u11A8"))), true);
		yield return () => ("a combining mark before a stable end", Dn(Rdn(Attribute(Organization, Utf8String, "e\u0301x"))), Dn(Rdn(Attribute(Organization, Utf8String, "\u00E9x"))), true);

		// Pairs that RFC 4518 makes equal by aligning what an unstable character expands or folds to with stable characters.
		yield return () => ("a full-width form at the start", Dn(Rdn(Attribute(Organization, Utf8String, "\uFF41bc"))), Dn(Rdn(Attribute(Organization, Utf8String, "abc"))), true);
		yield return () => ("a full-width form at the end", Dn(Rdn(Attribute(Organization, Utf8String, "ab\uFF23"))), Dn(Rdn(Attribute(Organization, Utf8String, "abc"))), true);
		yield return () => ("a ligature that expands", Dn(Rdn(Attribute(Organization, Utf8String, "\uFB01x"))), Dn(Rdn(Attribute(Organization, Utf8String, "fix"))), true);
		yield return () => ("a sharp s that folds to two letters", Dn(Rdn(Attribute(Organization, Utf8String, "stra\u00DFe"))), Dn(Rdn(Attribute(Organization, Utf8String, "strasse"))), true);
		yield return () => ("a Kelvin sign that folds to a letter", Dn(Rdn(Attribute(Organization, Utf8String, "\u212Ax"))), Dn(Rdn(Attribute(Organization, Utf8String, "kx"))), true);
		yield return () => ("a circled digit that normalizes to a digit", Dn(Rdn(Attribute(Organization, Utf8String, "x\u2460"))), Dn(Rdn(Attribute(Organization, Utf8String, "x1"))), true);
		yield return () => ("a space before a character that normalizes to one", Dn(Rdn(Attribute(Organization, Utf8String, "a \u00A8"))), Dn(Rdn(Attribute(Organization, Utf8String, "a\u00A8"))), true);
		yield return () => ("spaces before a full-width form that normalizes to a letter", Dn(Rdn(Attribute(Organization, Utf8String, "x   \uFF41"))), Dn(Rdn(Attribute(Organization, Utf8String, "x a"))), true);

		// Spaces that the preparation removes before an unstable character could count, so that an exact comparison cannot tell those values apart.
		yield return () => ("a space at the start before a combining mark", Dn(Rdn(Attribute(Organization, Utf8String, " \u0301a"))), Dn(Rdn(Attribute(Organization, Utf8String, "\u0301a"))), true);

		// A value without prepared text has no characters to compare, so an unstable one on the other side stands for it.
		yield return () => ("a value that is not a string against an unstable one", Dn(Rdn(Attribute(Organization, 0x04, "Evil Corp"))), Dn(Rdn(Attribute(Organization, Utf8String, "M\u00FCller GmbH"))), true);
		yield return () => ("an unstable value against one that does not decode", Dn(Rdn(Attribute(Organization, Utf8String, "M\u00FCller GmbH"))), Dn(Rdn(AttributeOf(Organization, Utf8String, [(byte)'E', 0xFF]))), true);
		yield return () => ("a value that is not a string against a stable one", Dn(Rdn(Attribute(Organization, 0x04, "abc"))), Dn(Rdn(Attribute(Organization, Utf8String, "abd"))), false);

		// A relaxed comparison is of the same type, in the same structure as IsWithin.
		yield return () => ("another type", Dn(Rdn(Attribute(CommonName, Utf8String, "É"))), Dn(Rdn(Attribute(Organization, Utf8String, "é"))), false);
		yield return () => ("a shorter name", Dn(Rdn(Attribute(Organization, Utf8String, "É"))), Dn(Rdn(Attribute(Organization, Utf8String, "é")), Rdn(Attribute(CommonName, Utf8String, "x"))), false);
		yield return () => ("a longer name", Dn(Rdn(Attribute(Organization, Utf8String, "É")), Rdn(Attribute(CommonName, Utf8String, "x"))), Dn(Rdn(Attribute(Organization, Utf8String, "é"))), true);
		yield return () => ("a relative name that cannot match", Dn(Rdn(Attribute(Country, PrintableString, "US")), Rdn(Attribute(CommonName, Utf8String, "É"))), Dn(Rdn(Attribute(Country, PrintableString, "CN")), Rdn(Attribute(CommonName, Utf8String, "é"))), false);
		yield return () => ("a value that is not a string", Dn(Rdn(Attribute(Organization, 0x04, "É"))), Dn(Rdn(Attribute(Organization, 0x04, "é"))), false);

		// Relative names of several attributes, where the attribute that could be anything of its type must not take the place of one that only its equal can fill.
		yield return () => ("the unstable attribute sorted first", Dn(Rdn(Attribute(CommonName, Utf8String, "É"), Attribute(CommonName, PrintableString, "ab"))), Dn(Rdn(Attribute(CommonName, PrintableString, "ab"), Attribute(CommonName, PrintableString, "cd"))), true);
		yield return () => ("the unstable attribute in the subtree", Dn(Rdn(Attribute(CommonName, PrintableString, "ab"), Attribute(CommonName, PrintableString, "cd"))), Dn(Rdn(Attribute(CommonName, Utf8String, "É"), Attribute(CommonName, PrintableString, "ab"))), true);
		yield return () => ("one unstable attribute for two that differ", Dn(Rdn(Attribute(CommonName, Utf8String, "É"), Attribute(CommonName, PrintableString, "ab"))), Dn(Rdn(Attribute(CommonName, PrintableString, "cd"), Attribute(CommonName, PrintableString, "ef"))), false);
		yield return () => ("the unstable attribute of another type than the one left", Dn(Rdn(Attribute(CommonName, Utf8String, "É"), Attribute(Organization, PrintableString, "ab"))), Dn(Rdn(Attribute(CommonName, PrintableString, "ab"), Attribute(Organization, PrintableString, "cd"))), false);
		yield return () => ("unstable attributes on both sides", Dn(Rdn(Attribute(CommonName, Utf8String, "É"), Attribute(CommonName, PrintableString, "ab"))), Dn(Rdn(Attribute(CommonName, Utf8String, "è"), Attribute(CommonName, PrintableString, "cd"))), true);
		yield return () => ("an unstable attribute for another with other ends", Dn(Rdn(Attribute(CommonName, Utf8String, "Müller"), Attribute(CommonName, PrintableString, "ab"))), Dn(Rdn(Attribute(CommonName, PrintableString, "ab"), Attribute(CommonName, PrintableString, "Schmidt"))), true);
		yield return () => ("another number of attributes", Dn(Rdn(Attribute(CommonName, Utf8String, "É"))), Dn(Rdn(Attribute(CommonName, Utf8String, "é"), Attribute(CommonName, PrintableString, "cd"))), false);
		yield return () => ("many attributes", Dn(Rdn([.. Enumerable.Range(0, 80).Select(static i => Attribute(CommonName, Utf8String, $"É{i}"))])), Dn(Rdn([.. Enumerable.Range(0, 80).Select(static i => Attribute(CommonName, Utf8String, $"é{i}"))])), true);

		// RFC 5280, Sec. 7.3, asks for a case-insensitive exact match of domainComponent values, but LDAP compares them by caseIgnoreIA5Match (RFC 4519), which ignores insignificant spaces (RFC 4517, Sec. 4.2.7): values equal by either rule could match, while different labels stay apart; a character beyond ASCII could still fold to another.
		yield return () => ("a domain component of another case", Dn(Rdn(Attribute(DomainComponent, Ia5String, "COM"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"))), true);
		yield return () => ("a domain component with a space at the end", Dn(Rdn(Attribute(DomainComponent, Ia5String, "com "))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"))), true);
		yield return () => ("a domain component with a control code", Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"))), true);
		yield return () => ("domain components with a space, among others", Dn(Rdn(Attribute(DomainComponent, Ia5String, "a "), Attribute(DomainComponent, Ia5String, "b"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "a"), Attribute(DomainComponent, Ia5String, "b"))), true);
		yield return () => ("a domain component of another case outside ASCII", Dn(Rdn(Attribute(DomainComponent, Utf8String, "É"))), Dn(Rdn(Attribute(DomainComponent, Utf8String, "é"))), true);
		yield return () => ("a domain component with a Kelvin sign", Dn(Rdn(Attribute(DomainComponent, Utf8String, "K"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "k"))), true);
		yield return () => ("a domain component with a space at the start", Dn(Rdn(Attribute(DomainComponent, Ia5String, " com"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"))), true);
		yield return () => ("a domain component with a space at the end, in the subtree", Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "com "))), true);
		yield return () => ("a domain component with spaces inside", Dn(Rdn(Attribute(DomainComponent, Ia5String, "a  b"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "a b"))), true);
		yield return () => ("a domain component with a tab for a space", Dn(Rdn(Attribute(DomainComponent, Ia5String, "a\tb"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "a b"))), true);
		yield return () => ("a domain component in UTF8String with a space at the end", Dn(Rdn(Attribute(DomainComponent, Utf8String, "COM "))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"))), true);
		yield return () => ("a domain component with a soft hyphen", Dn(Rdn(Attribute(DomainComponent, Utf8String, "c\u00ADom"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"))), true);
		yield return () => ("another domain component", Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "org"))), false);
		yield return () => ("a longer domain component", Dn(Rdn(Attribute(DomainComponent, Ia5String, "comx"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"))), false);
		yield return () => ("a domain component split by a space", Dn(Rdn(Attribute(DomainComponent, Ia5String, "co m"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"))), false);
		yield return () => ("a domain component that spaces bring within reach of an unstable character", Dn(Rdn(Attribute(DomainComponent, Utf8String, "é x "))), Dn(Rdn(Attribute(DomainComponent, Utf8String, "éz x"))), true);
		yield return () => ("a domain component with spaces, among others of other types", Dn(Rdn(Attribute(DomainComponent, Ia5String, " com"), Attribute(CommonName, PrintableString, "x"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "com"), Attribute(CommonName, PrintableString, "x"))), true);
		yield return () => ("domain components with a space, among others that differ", Dn(Rdn(Attribute(DomainComponent, Ia5String, "a "), Attribute(DomainComponent, Ia5String, "b"))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "a"), Attribute(DomainComponent, Ia5String, "c"))), false);
		yield return () => ("a domain component with a space, beside an unstable one", Dn(Rdn(Attribute(DomainComponent, Utf8String, "É"), Attribute(DomainComponent, Ia5String, "a "))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "a"), Attribute(DomainComponent, Ia5String, "x"))), true);
		yield return () => ("a domain component with a space, beside an unstable one, for others that differ", Dn(Rdn(Attribute(DomainComponent, Utf8String, "É"), Attribute(DomainComponent, Ia5String, "a "))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "b"), Attribute(DomainComponent, Ia5String, "x"))), false);

		// RFC 2985, Sec. 6.1, gives emailAddress and unstructuredName the same characters but for case, but RFC 5280, Sec. 7.1, only requires caseIgnoreMatch, by which a relying party would prepare them by RFC 4518: values equal by either rule could match, while different values stay apart; a character beyond ASCII could still fold to another.
		foreach ((string type, string label) in CaseIgnoreTypes)
		{
			yield return () => ($"{label} of another case", Dn(Rdn(Attribute(type, Ia5String, "A@EXAMPLE.COM"))), Dn(Rdn(Attribute(type, Ia5String, "a@example.com"))), true);
			yield return () => ($"{label} with a space at the end", Dn(Rdn(Attribute(type, Ia5String, "a@example.com "))), Dn(Rdn(Attribute(type, Ia5String, "a@example.com"))), true);
			yield return () => ($"{label} with a space at the start", Dn(Rdn(Attribute(type, Ia5String, " a@example.com"))), Dn(Rdn(Attribute(type, Ia5String, "a@example.com"))), true);
			yield return () => ($"{label} with a space at the end, in the subtree", Dn(Rdn(Attribute(type, Ia5String, "a@example.com"))), Dn(Rdn(Attribute(type, Ia5String, "a@example.com "))), true);
			yield return () => ($"{label} with spaces inside", Dn(Rdn(Attribute(type, Ia5String, "a  b"))), Dn(Rdn(Attribute(type, Ia5String, "a b"))), true);
			yield return () => ($"{label} with a tab for a space", Dn(Rdn(Attribute(type, Ia5String, "a\tb"))), Dn(Rdn(Attribute(type, Ia5String, "a b"))), true);
			yield return () => ($"{label} with a control code", Dn(Rdn(Attribute(type, Ia5String, "a@exa\u0001mple.com"))), Dn(Rdn(Attribute(type, Ia5String, "a@example.com"))), true);
			yield return () => ($"{label} with a soft hyphen", Dn(Rdn(Attribute(type, Utf8String, "a@exa\u00ADmple.com"))), Dn(Rdn(Attribute(type, Ia5String, "a@example.com"))), true);
			yield return () => ($"{label} in BMPString with a space at the end", Dn(Rdn(AttributeOf(type, BmpString, Encoding.BigEndianUnicode.GetBytes("A@EXAMPLE.COM ")))), Dn(Rdn(Attribute(type, Ia5String, "a@example.com"))), true);
			yield return () => ($"{label} of another case outside ASCII", Dn(Rdn(Attribute(type, Utf8String, "É"))), Dn(Rdn(Attribute(type, Utf8String, "é"))), true);
			yield return () => ($"another {label}", Dn(Rdn(Attribute(type, Ia5String, "a@example.com"))), Dn(Rdn(Attribute(type, Ia5String, "b@example.com"))), false);
			yield return () => ($"a longer {label}", Dn(Rdn(Attribute(type, Ia5String, "a@example.comx"))), Dn(Rdn(Attribute(type, Ia5String, "a@example.com"))), false);
			yield return () => ($"{label} split by a space", Dn(Rdn(Attribute(type, Ia5String, "a@exa mple.com"))), Dn(Rdn(Attribute(type, Ia5String, "a@example.com"))), false);
			yield return () => ($"{label} with spaces, among others of other types", Dn(Rdn(Attribute(type, Ia5String, " a@example.com"), Attribute(CommonName, PrintableString, "x"))), Dn(Rdn(Attribute(type, Ia5String, "a@example.com"), Attribute(CommonName, PrintableString, "x"))), true);
			yield return () => ($"{label} with a space, among others that differ", Dn(Rdn(Attribute(type, Ia5String, "a@example.com "), Attribute(CommonName, PrintableString, "x"))), Dn(Rdn(Attribute(type, Ia5String, "a@example.com"), Attribute(CommonName, PrintableString, "y"))), false);
			yield return () => ($"{label} with a space, beside an unstable one", Dn(Rdn(Attribute(type, Utf8String, "É"), Attribute(type, Ia5String, "a "))), Dn(Rdn(Attribute(type, Ia5String, "a"), Attribute(type, Ia5String, "x"))), true);
		}
	}

	[Test]
	[MethodDataSource(nameof(UnstableCases))]
	public async Task TellsWhatACompleteComparisonCouldFindWithin(string @case, byte[] name, byte[] subtree, bool mightBeWithin)
	{
		DistinguishedName parsedName = DistinguishedName.Read(name);
		DistinguishedName parsedSubtree = DistinguishedName.Read(subtree);

		await Assert.That(parsedName.MightBeWithin(parsedSubtree)).IsEqualTo(mightBeWithin).Because(@case);
	}

	public static IEnumerable<Func<(string Case, byte[] Left, byte[] Right, bool Equal)>> EqualityCases()
	{
		yield return () => ("identical", Dn(Rdn(Attribute(Country, PrintableString, "US")), Rdn(Attribute(CommonName, PrintableString, "Example"))), Dn(Rdn(Attribute(Country, PrintableString, "US")), Rdn(Attribute(CommonName, PrintableString, "Example"))), true);
		yield return () => ("the empty name", Dn(), Dn(), true);

		// Sec. 7.1, as IsWithin compares relative names.
		yield return () => ("another string type and case", Dn(Rdn(Attribute(Country, PrintableString, "US")), Rdn(Attribute(CommonName, PrintableString, "Example CA"))), Dn(Rdn(Attribute(Country, Utf8String, "us")), Rdn(Attribute(CommonName, Utf8String, "EXAMPLE CA"))), true);
		yield return () => ("insignificant spaces", Dn(Rdn(Attribute(CommonName, PrintableString, " Example  CA "))), Dn(Rdn(Attribute(CommonName, Utf8String, "Example CA"))), true);
		yield return () => ("a BMPString", Dn(Rdn(AttributeOf(CommonName, BmpString, Encoding.BigEndianUnicode.GetBytes("Example")))), Dn(Rdn(Attribute(CommonName, PrintableString, "EXAMPLE"))), true);
		yield return () => ("a domain component of another case", Dn(Rdn(Attribute(DomainComponent, Ia5String, "Example"))), Dn(Rdn(Attribute(DomainComponent, Utf8String, "eXAMPLE"))), true);
		yield return () => ("two attributes in another order", Dn(Rdn(Attribute(CommonName, PrintableString, "a"), Attribute(Organization, PrintableString, "b"))), Dn(Rdn(Attribute(Organization, Utf8String, "B"), Attribute(CommonName, Utf8String, "A"))), true);

		// The exact comparison tells them apart, as does the comparison of the letters and digits before it.
		yield return () => ("another value", Dn(Rdn(Attribute(CommonName, PrintableString, "Example CA"))), Dn(Rdn(Attribute(CommonName, PrintableString, "Example CA 2"))), false);
		yield return () => ("another letter beyond what the comparison before reads", Dn(Rdn(AttributeOf(CommonName, BmpString, Encoding.BigEndianUnicode.GetBytes("ab")))), Dn(Rdn(Attribute(CommonName, PrintableString, "ac"))), false);
		yield return () => ("a space removed", Dn(Rdn(Attribute(CommonName, PrintableString, "Example CA"))), Dn(Rdn(Attribute(CommonName, PrintableString, "ExampleCA"))), false);
		yield return () => ("another type", Dn(Rdn(Attribute(Organization, PrintableString, "Example"))), Dn(Rdn(Attribute(CommonName, PrintableString, "Example"))), false);
		yield return () => ("another case outside ASCII", Dn(Rdn(Attribute(CommonName, Utf8String, "Éa"))), Dn(Rdn(Attribute(CommonName, Utf8String, "éA"))), false);
		yield return () => ("a domain component with a space", Dn(Rdn(Attribute(DomainComponent, Ia5String, "com "))), Dn(Rdn(Attribute(DomainComponent, Ia5String, "COM"))), false);
		yield return () => ("invalid UTF-8 of another case", Dn(Rdn(AttributeOf(CommonName, Utf8String, [(byte)'a', 0xFF]))), Dn(Rdn(AttributeOf(CommonName, Utf8String, [(byte)'A', 0xFF]))), false);
		yield return () => ("another attribute among two", Dn(Rdn(Attribute(CommonName, PrintableString, "a"), Attribute(Organization, PrintableString, "b"))), Dn(Rdn(Attribute(CommonName, PrintableString, "a"), Attribute(Organization, PrintableString, "c"))), false);

		// The names are the same, not one within the other.
		yield return () => ("a longer name", Dn(Rdn(Attribute(Country, PrintableString, "US")), Rdn(Attribute(CommonName, PrintableString, "x"))), Dn(Rdn(Attribute(Country, Utf8String, "us"))), false);
		yield return () => ("a shorter name", Dn(Rdn(Attribute(Country, Utf8String, "us"))), Dn(Rdn(Attribute(Country, PrintableString, "US")), Rdn(Attribute(CommonName, PrintableString, "x"))), false);
		yield return () => ("the empty name and another", Dn(), Dn(Rdn(Attribute(CommonName, PrintableString, "x"))), false);
		yield return () => ("a longer name with several attributes", Dn(Rdn(Attribute(CommonName, PrintableString, "a"), Attribute(Organization, PrintableString, "b")), Rdn(Attribute(CommonName, PrintableString, "x"))), Dn(Rdn(Attribute(CommonName, Utf8String, "A"), Attribute(Organization, Utf8String, "B"))), false);
	}

	// RFC 5280, Sec. 7.1: AreEqual finds two Names the same as IsWithin compares them, whichever comes first, and only with as many relative names.
	[Test]
	[MethodDataSource(nameof(EqualityCases))]
	public async Task FindsNamesTheSameAsRfc5280Requires(string @case, byte[] left, byte[] right, bool equal)
	{
		using (Assert.Multiple())
		{
			await Assert.That(DistinguishedName.AreEqual(left, right)).IsEqualTo(equal).Because(@case);
			await Assert.That(DistinguishedName.AreEqual(right, left)).IsEqualTo(equal).Because(@case);
		}
	}

	// The path search compares the issuer and the subject of every certificate, which mostly differ in the letters of a value: that takes no allocation.
	[Test]
	public async Task TellsApartNamesOfOtherLettersWithoutAllocating()
	{
		byte[] issuer = Dn(Rdn(Attribute(Country, PrintableString, "US")), Rdn(Attribute(Organization, PrintableString, "Example")), Rdn(Attribute(CommonName, PrintableString, "Example Issuing CA")));
		byte[] subject = Dn(Rdn(Attribute(Country, PrintableString, "US")), Rdn(Attribute(Organization, Utf8String, "Example")), Rdn(Attribute(CommonName, Utf8String, "www.example.com")));

		await Assert.That(MeasureAllocation(issuer, subject)).IsEqualTo(0);

		static long MeasureAllocation(byte[] left, byte[] right)
		{
			_ = DistinguishedName.AreEqual(left, right);
			long before = GC.GetAllocatedBytesForCurrentThread();
			bool equal = DistinguishedName.AreEqual(left, right);
			long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
			return equal ? -1 : allocated;
		}
	}

	// A pair of Names whose comparison could take more than MaxEqualityWork counts as different, unless identical; the work is that of Work.
	[Test]
	public async Task FindsNamesDifferentBeyondTheLimitOfWork()
	{
		byte[] large = Dn(Rdn([.. Enumerable.Range(0, 1023).Select(static i => Attribute(CommonName, PrintableString, $"v{i}"))]));
		byte[] largeOtherCase = Dn(Rdn([.. Enumerable.Range(0, 1023).Select(static i => Attribute(CommonName, PrintableString, $"V{i}"))]));
		byte[] larger = Dn(Rdn([.. Enumerable.Range(0, 1024).Select(static i => Attribute(CommonName, PrintableString, $"v{i}"))]));
		byte[] largerOtherCase = Dn(Rdn([.. Enumerable.Range(0, 1024).Select(static i => Attribute(CommonName, PrintableString, $"V{i}"))]));

		using (Assert.Multiple())
		{
			await Assert.That(DistinguishedName.Read(large).Work * DistinguishedName.Read(largeOtherCase).Work).IsEqualTo(DistinguishedName.MaxEqualityWork);
			await Assert.That(DistinguishedName.AreEqual(large, largeOtherCase)).IsTrue();
			await Assert.That(DistinguishedName.AreEqual(larger, largerOtherCase)).IsFalse();
			await Assert.That(DistinguishedName.AreEqual(larger, larger)).IsTrue();
		}
	}

	// Each attribute and every 64 bytes of it count, once, so that the cost bounds the work of a comparison, whatever the shape of the Name.
	[Test]
	public async Task CountsTheAttributesAndTheirLengthInTheCost()
	{
		DistinguishedName small = DistinguishedName.Read(Dn(Rdn(Attribute(CommonName, PrintableString, "a"), Attribute(Organization, PrintableString, "b"))));
		DistinguishedName longValue = DistinguishedName.Read(Dn(Rdn(Attribute(CommonName, PrintableString, new string('a', 640)))));

		using (Assert.Multiple())
		{
			await Assert.That(DistinguishedName.Read(Dn()).Work).IsEqualTo(1);
			await Assert.That(small.Work).IsEqualTo(3);
			await Assert.That(longValue.Work).IsEqualTo(12);
		}
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
		return AttributeOf(type, tag, Encoding.UTF8.GetBytes(value));
	}

	private static byte[] AttributeOf(string type, byte tag, byte[] value)
	{
		return Sequence(Oid(type), Tlv(tag, value));
	}
}
