using CryptoBase.DataFormatExtensions;
using System.Buffers;
using static CryptoBase.Tests.DataFormatExtensions.Base32TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.DataFormatExtensions;

public class Base32CustomAlphabetTest
{
	[Test]
	[MatrixDataSource]
	public async Task CustomAlphabetAndPaddingRoundTrip([Matrix] bool omitPadding)
	{
		const string alphabet = "abcdefghijklmnopqrstuvwxyz234567";
		const char padding = '~';
		byte[] source = Enumerable.Range(0, 73).Select(static value => (byte)(value * 37 + 11)).ToArray();
		Base32Encoding custom = Base32Encoding.Create(alphabet, padding);
		Base32Encoding encoding = omitPadding ? custom.OmitPadding : custom;

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
	[MatrixDataSource]
	public async Task CustomAlphabetHandlesSimdBoundaries([Matrix(10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 39, 40, 41, 79, 80, 81, 160, 205)] int sourceLength, [Matrix] bool omitPadding)
	{
		const string alphabet = "abcdefghijklmnopqrstuvwxyz234567";
		const char padding = '~';
		Base32Encoding custom = Base32Encoding.Create(alphabet, padding);
		Base32Encoding encoding = omitPadding ? custom.OmitPadding : custom;

		byte[] source = new byte[sourceLength];

		for (int i = 0; i < source.Length; ++i)
		{
			source[i] = (byte)(i * 37 + sourceLength * 11);
		}

		char[] expected = EncodeReference(source, alphabet, padding, omitPadding);
		byte[] expectedUtf8 = ToByteSymbols(expected);
		char[] encodedChars = new char[expected.Length];
		byte[] encodedUtf8 = new byte[expected.Length];
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
	[MatrixDataSource]
	public async Task CustomAlphabetCharSimdDecodeReportsInvalidDataLikeScalar([Matrix('!', '\u0080', '\u0100')] char invalidSymbol, [Matrix(15, 16, 63, 64, 127, 128, 255, 327)] int invalidOffset)
	{
		const string alphabet = "abcdefghijklmnopqrstuvwxyz234567";
		const int sourceLength = 205;
		Base32Encoding encoding = Base32Encoding.Create(alphabet);
		byte[] source = new byte[sourceLength];

		for (int i = 0; i < source.Length; ++i)
		{
			source[i] = (byte)(i * 37 + 11);
		}

		char[] encodedChars = EncodeReference(source, alphabet, '=', false);
		encodedChars[invalidOffset] = invalidSymbol;
		byte[] scalarDestination = Enumerable.Repeat(DestinationSentinel, sourceLength).ToArray();
		byte[] autoDestination = Enumerable.Repeat(DestinationSentinel, sourceLength).ToArray();

		OperationStatus scalarStatus = encoding.DecodeFromCharsPath(encodedChars, scalarDestination, out int scalarConsumed, out int scalarWritten, true, Base32SimdPath.Scalar);
		OperationStatus autoStatus = encoding.DecodeFromChars(encodedChars, autoDestination, out int autoConsumed, out int autoWritten);

		int expectedConsumed = invalidOffset / 8 * 8;
		byte[] expected = source.AsSpan().Slice(0, invalidOffset / 8 * 5).ToArray();
		await Assert.That(scalarStatus).IsEqualTo(OperationStatus.InvalidData);
		await Assert.That(autoStatus).IsEqualTo(OperationStatus.InvalidData);
		await Assert.That(scalarConsumed).IsEqualTo(expectedConsumed);
		await Assert.That(autoConsumed).IsEqualTo(expectedConsumed);
		await AssertOutput(scalarDestination, expected, scalarWritten);
		await AssertOutput(autoDestination, expected, autoWritten);
	}

	[Test]
	[MatrixDataSource]
	public async Task CustomAlphabetUtf8SimdDecodeReportsInvalidDataLikeScalar([Matrix((byte)'!', (byte)0x80, (byte)0xff)] byte invalidSymbol, [Matrix(15, 16, 63, 64, 127, 128, 255, 327)] int invalidOffset)
	{
		const string alphabet = "abcdefghijklmnopqrstuvwxyz234567";
		const int sourceLength = 205;
		Base32Encoding encoding = Base32Encoding.Create(alphabet);
		byte[] source = new byte[sourceLength];

		for (int i = 0; i < source.Length; ++i)
		{
			source[i] = (byte)(i * 37 + 11);
		}

		byte[] encodedUtf8 = ToByteSymbols(EncodeReference(source, alphabet, '=', false));
		encodedUtf8[invalidOffset] = invalidSymbol;
		byte[] scalarDestination = Enumerable.Repeat(DestinationSentinel, sourceLength).ToArray();
		byte[] autoDestination = Enumerable.Repeat(DestinationSentinel, sourceLength).ToArray();

		OperationStatus scalarStatus = encoding.DecodeFromUtf8Path(encodedUtf8, scalarDestination, out int scalarConsumed, out int scalarWritten, true, Base32SimdPath.Scalar);
		OperationStatus autoStatus = encoding.DecodeFromUtf8(encodedUtf8, autoDestination, out int autoConsumed, out int autoWritten);

		int expectedConsumed = invalidOffset / 8 * 8;
		byte[] expected = source.AsSpan().Slice(0, invalidOffset / 8 * 5).ToArray();
		await Assert.That(scalarStatus).IsEqualTo(OperationStatus.InvalidData);
		await Assert.That(autoStatus).IsEqualTo(OperationStatus.InvalidData);
		await Assert.That(scalarConsumed).IsEqualTo(expectedConsumed);
		await Assert.That(autoConsumed).IsEqualTo(expectedConsumed);
		await AssertOutput(scalarDestination, expected, scalarWritten);
		await AssertOutput(autoDestination, expected, autoWritten);
	}

	[Test]
	public async Task InvalidConfigurationIsRejected()
	{
		const string alphabet = "abcdefghijklmnopqrstuvwxyz234567";

		await Assert.That(() => Base32Encoding.Create(alphabet.Substring(1))).ThrowsExactly<ArgumentException>();
		await Assert.That(() => Base32Encoding.Create(alphabet + '8')).ThrowsExactly<ArgumentException>();
		await Assert.That(() => Base32Encoding.Create("abcdefghijklmnopqrstuvwxyz23456é")).ThrowsExactly<ArgumentException>();
		await Assert.That(() => Base32Encoding.Create("abcdefghijklmnopqrstuvwxyz23456a")).ThrowsExactly<ArgumentException>();
		await Assert.That(() => Base32Encoding.Create(alphabet, 'a')).ThrowsExactly<ArgumentException>();
		await Assert.That(() => Base32Encoding.Create(alphabet, '\0')).ThrowsExactly<ArgumentException>();
		await Assert.That(() => Base32Encoding.Create(alphabet, '\u0080')).ThrowsExactly<ArgumentException>();
	}
}
