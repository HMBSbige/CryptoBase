using CryptoBase.X509;
using System.Text;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.X509;

public class DistinguishedNameTest
{
	private const string CommonName = "2.5.4.3";
	private const string Organization = "2.5.4.10";
	private const string Country = "2.5.4.6";

	private const byte Utf8String = 0x0C;
	private const byte NumericString = 0x12;
	private const byte PrintableString = 0x13;
	private const byte TeletexString = 0x14;
	private const byte Ia5String = 0x16;
	private const byte VisibleString = 0x1A;
	private const byte UniversalString = 0x1C;
	private const byte BmpString = 0x1E;

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

		// Other types and values that do not decode compare byte for byte.
		yield return () => ("NumericString identical", Dn(Rdn(Attribute(CommonName, NumericString, "123"))), Dn(Rdn(Attribute(CommonName, NumericString, "123"))), true);
		yield return () => ("NumericString against PrintableString", Dn(Rdn(Attribute(CommonName, NumericString, "123"))), Dn(Rdn(Attribute(CommonName, PrintableString, "123"))), false);
		yield return () => ("OCTET STRING with another case", Dn(Rdn(Attribute(CommonName, 0x04, "aB"))), Dn(Rdn(Attribute(CommonName, 0x04, "Ab"))), false);
		yield return () => ("invalid UTF-8, identical", Dn(Rdn(AttributeOf(CommonName, Utf8String, [0xFF]))), Dn(Rdn(AttributeOf(CommonName, Utf8String, [0xFF]))), true);
		yield return () => ("invalid UTF-8, another case of the rest", Dn(Rdn(AttributeOf(CommonName, Utf8String, [(byte)'a', 0xFF]))), Dn(Rdn(AttributeOf(CommonName, Utf8String, [(byte)'A', 0xFF]))), false);
		yield return () => ("a BMPString of an odd length", Dn(Rdn(AttributeOf(CommonName, BmpString, [0x00]))), Dn(Rdn(AttributeOf(CommonName, BmpString, [0x00]))), true);
		yield return () => ("a UniversalString that is not valid, against text", Dn(Rdn(AttributeOf(CommonName, UniversalString, [0x7F, 0xFF, 0xFF, 0xFF]))), Dn(Rdn(Attribute(CommonName, Utf8String, ""))), false);

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
	}

	[Test]
	[MethodDataSource(nameof(UnstableCases))]
	public async Task TellsWhatACompleteComparisonCouldFindWithin(string @case, byte[] name, byte[] subtree, bool mightBeWithin)
	{
		DistinguishedName parsedName = DistinguishedName.Read(name);
		DistinguishedName parsedSubtree = DistinguishedName.Read(subtree);

		await Assert.That(parsedName.MightBeWithin(parsedSubtree)).IsEqualTo(mightBeWithin).Because(@case);
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
