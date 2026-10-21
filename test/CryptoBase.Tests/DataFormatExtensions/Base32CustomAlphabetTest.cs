using CryptoBase.DataFormatExtensions;
using System.Buffers;
using static CryptoBase.Tests.DataFormatExtensions.Base32TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.DataFormatExtensions;

public class Base32CustomAlphabetTest
{
	[Test]
	[MatrixDataSource]
	public async Task CustomAlphabetAndPaddingRoundTrip([Matrix(10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 39, 40, 41, 73, 79, 80, 81, 160, 205)] int sourceLength, [Matrix] bool omitPadding)
	{
		const string alphabet = LowercaseAlphabet;
		const char padding = '~';
		Base32Encoding custom = Base32Encoding.Create(alphabet, padding);
		Base32Encoding encoding = omitPadding ? custom.OmitPadding : custom;

		byte[] source = CreatePatternSource(sourceLength, sourceLength * 11);

		char[] expected = EncodeReference(source, alphabet, padding, omitPadding);
		byte[] expectedUtf8 = ToByteSymbols(expected);
		char[] encodedChars = new char[encoding.GetEncodedLength(source.Length)];
		byte[] encodedUtf8 = new byte[encoding.GetEncodedLength(source.Length)];
		byte[] decodedChars = new byte[source.Length];
		byte[] decodedUtf8 = new byte[source.Length];

		OperationStatus encodeCharStatus = encoding.EncodeToChars(source, encodedChars, out int encodeCharsConsumed, out int charsWritten);
		OperationStatus encodeUtf8Status = encoding.EncodeToUtf8(source, encodedUtf8, out int encodeBytesConsumed, out int bytesWritten);
		OperationStatus decodeCharStatus = encoding.DecodeFromChars(encodedChars, decodedChars, out int decodeCharsConsumed, out int charsDecoded);
		OperationStatus decodeUtf8Status = encoding.DecodeFromUtf8(encodedUtf8, decodedUtf8, out int decodeBytesConsumed, out int bytesDecoded);

		await Assert.That(encodeCharStatus).IsEqualTo(OperationStatus.Done);
		await Assert.That(encodeUtf8Status).IsEqualTo(OperationStatus.Done);
		await Assert.That(decodeCharStatus).IsEqualTo(OperationStatus.Done);
		await Assert.That(decodeUtf8Status).IsEqualTo(OperationStatus.Done);
		await Assert.That(encodeCharsConsumed).IsEqualTo(source.Length);
		await Assert.That(encodeBytesConsumed).IsEqualTo(source.Length);
		await Assert.That(charsWritten).IsEqualTo(expected.Length);
		await Assert.That(bytesWritten).IsEqualTo(expected.Length);
		await Assert.That(decodeCharsConsumed).IsEqualTo(expected.Length);
		await Assert.That(decodeBytesConsumed).IsEqualTo(expected.Length);
		await Assert.That(charsDecoded).IsEqualTo(source.Length);
		await Assert.That(bytesDecoded).IsEqualTo(source.Length);
		await Assert.That(encodedChars).IsEquivalentTo(expected, CollectionOrdering.Matching);
		await Assert.That(encodedUtf8).IsEquivalentTo(expectedUtf8, CollectionOrdering.Matching);
		await Assert.That(decodedChars).IsEquivalentTo(source, CollectionOrdering.Matching);
		await Assert.That(decodedUtf8).IsEquivalentTo(source, CollectionOrdering.Matching);
	}

	[Test]
	public async Task CustomAlphabetEncodeMatchesReferenceForEveryLength()
	{
		const string alphabet = LowercaseAlphabet;
		const char padding = '~';
		const char charSentinel = (char)0xA5A5;
		Base32Encoding encoding = Base32Encoding.Create(alphabet, padding);
		byte[] source = CreateDeterministicSource(240);
		byte[] utf8Actual = new byte[encoding.GetEncodedLength(source.Length) + 64];
		char[] charsActual = new char[utf8Actual.Length];
		List<string> failures = [];

		for (int length = 0; length <= source.Length; ++length)
		{
			ReadOnlySpan<byte> input = source.AsSpan(0, length);
			char[] expected = EncodeReference(input, alphabet, padding, false);
			byte[] expectedUtf8 = ToByteSymbols(expected);
			PrepareDestination(utf8Actual);
			charsActual.AsSpan().Fill(charSentinel);

			OperationStatus utf8Status = encoding.EncodeToUtf8(input, utf8Actual.AsSpan(0, expected.Length), out int utf8Consumed, out int utf8Written);
			OperationStatus charsStatus = encoding.EncodeToChars(input, charsActual.AsSpan(0, expected.Length), out int charsConsumed, out int charsWritten);

			if (utf8Status is not OperationStatus.Done || utf8Consumed != length || utf8Written != expected.Length || !utf8Actual.AsSpan(0, expected.Length).SequenceEqual(expectedUtf8) || utf8Actual.AsSpan(expected.Length).ContainsAnyExcept(DestinationSentinel))
			{
				failures.Add($"UTF-8 {length}: {utf8Status}/{utf8Consumed}/{utf8Written}");
			}

			if (charsStatus is not OperationStatus.Done || charsConsumed != length || charsWritten != expected.Length || !charsActual.AsSpan(0, expected.Length).SequenceEqual(expected) || charsActual.AsSpan(expected.Length).ContainsAnyExcept(charSentinel))
			{
				failures.Add($"Chars {length}: {charsStatus}/{charsConsumed}/{charsWritten}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MatrixDataSource]
	public async Task CustomAlphabetCharDecodeReportsInvalidData([Matrix('!', '\u0080', '\u0100')] char invalidSymbol, [Matrix(15, 16, 63, 64, 127, 128, 255, 327)] int invalidOffset)
	{
		const string alphabet = LowercaseAlphabet;
		const int sourceLength = 205;
		Base32Encoding encoding = Base32Encoding.Create(alphabet);
		byte[] source = CreatePatternSource(sourceLength, 11);

		char[] encodedChars = EncodeReference(source, alphabet, '=', false);
		encodedChars[invalidOffset] = invalidSymbol;
		byte[] destination = new byte[sourceLength];
		PrepareDestination(destination);

		OperationStatus status = encoding.DecodeFromChars(encodedChars, destination, out int consumed, out int written);

		int expectedConsumed = invalidOffset / 8 * 8;
		byte[] expected = source.AsSpan().Slice(0, invalidOffset / 8 * 5).ToArray();
		await Assert.That(status).IsEqualTo(OperationStatus.InvalidData);
		await Assert.That(consumed).IsEqualTo(expectedConsumed);
		await AssertOutput(destination, expected, written);
	}

	[Test]
	[MatrixDataSource]
	public async Task CustomAlphabetWithControlSymbolsRejectsWideChars([Matrix(0x0080, 0x00FF, 0x0100, 0x017F, 0x7FFF, 0x8000, 0xFF00, 0xFFFF)] int invalidSymbol, [Matrix(15, 64, 127, 128, 327)] int invalidOffset)
	{
		const string alphabet = "\0abcdefghijklmnopqrstuvwxyz2345\u007f";
		const int sourceLength = 205;
		Base32Encoding encoding = Base32Encoding.Create(alphabet);
		byte[] source = CreateDeterministicSource(sourceLength);
		char[] encodedChars = EncodeReference(source, alphabet, '=', false);
		encodedChars[invalidOffset] = (char)invalidSymbol;
		byte[] destination = new byte[sourceLength];
		PrepareDestination(destination);

		OperationStatus status = encoding.DecodeFromChars(encodedChars, destination, out int consumed, out int written);

		byte[] expected = source.AsSpan().Slice(0, invalidOffset / 8 * 5).ToArray();
		await Assert.That(status).IsEqualTo(OperationStatus.InvalidData);
		await Assert.That(consumed).IsEqualTo(invalidOffset / 8 * 8);
		await AssertOutput(destination, expected, written);
	}

	[Test]
	[MatrixDataSource]
	public async Task CustomAlphabetUtf8DecodeReportsInvalidData([Matrix((byte)'!', (byte)0x80, (byte)0xff)] byte invalidSymbol, [Matrix(15, 16, 63, 64, 127, 128, 255, 327)] int invalidOffset)
	{
		const string alphabet = LowercaseAlphabet;
		const int sourceLength = 205;
		Base32Encoding encoding = Base32Encoding.Create(alphabet);
		byte[] source = CreatePatternSource(sourceLength, 11);

		byte[] encodedUtf8 = ToByteSymbols(EncodeReference(source, alphabet, '=', false));
		encodedUtf8[invalidOffset] = invalidSymbol;
		byte[] destination = new byte[sourceLength];
		PrepareDestination(destination);

		OperationStatus status = encoding.DecodeFromUtf8(encodedUtf8, destination, out int consumed, out int written);

		int expectedConsumed = invalidOffset / 8 * 8;
		byte[] expected = source.AsSpan().Slice(0, invalidOffset / 8 * 5).ToArray();
		await Assert.That(status).IsEqualTo(OperationStatus.InvalidData);
		await Assert.That(consumed).IsEqualTo(expectedConsumed);
		await AssertOutput(destination, expected, written);
	}

	[Test]
	public async Task InvalidConfigurationIsRejected()
	{
		const string alphabet = LowercaseAlphabet;

		await Assert.That(() => Base32Encoding.Create(alphabet.Substring(1))).ThrowsExactly<ArgumentException>();
		await Assert.That(() => Base32Encoding.Create(alphabet + '8')).ThrowsExactly<ArgumentException>();
		await Assert.That(() => Base32Encoding.Create("abcdefghijklmnopqrstuvwxyz23456é")).ThrowsExactly<ArgumentException>();
		await Assert.That(() => Base32Encoding.Create("abcdefghijklmnopqrstuvwxyz23456a")).ThrowsExactly<ArgumentException>();
		await Assert.That(() => Base32Encoding.Create(alphabet, 'a')).ThrowsExactly<ArgumentException>();
		await Assert.That(() => Base32Encoding.Create(alphabet, '\0')).ThrowsExactly<ArgumentException>();
		await Assert.That(() => Base32Encoding.Create(alphabet, '\u0080')).ThrowsExactly<ArgumentException>();
	}
}
