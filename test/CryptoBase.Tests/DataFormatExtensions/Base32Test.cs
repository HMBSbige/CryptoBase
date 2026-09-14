using CryptoBase.DataFormatExtensions;
using System.Buffers;
using System.Text;
using static CryptoBase.Tests.DataFormatExtensions.Base32TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.DataFormatExtensions;

public class Base32Test
{
	public static IEnumerable<int> SourceLengths()
	{
		return Enumerable.Range(0, 206).Append(1040);
	}

	[Test]
	[Arguments(false, @"", @"")]
	[Arguments(false, @"f", @"MY======")]
	[Arguments(false, @"fo", @"MZXQ====")]
	[Arguments(false, @"foo", @"MZXW6===")]
	[Arguments(false, @"foob", @"MZXW6YQ=")]
	[Arguments(false, @"fooba", @"MZXW6YTB")]
	[Arguments(false, @"foobar", @"MZXW6YTBOI======")]
	[Arguments(true, @"", @"")]
	[Arguments(true, @"f", @"CO======")]
	[Arguments(true, @"fo", @"CPNG====")]
	[Arguments(true, @"foo", @"CPNMU===")]
	[Arguments(true, @"foob", @"CPNMUOG=")]
	[Arguments(true, @"fooba", @"CPNMUOJ1")]
	[Arguments(true, @"foobar", @"CPNMUOJ1E8======")]
	public async Task Rfc4648VectorsRoundTrip(bool hex, string originExpected, string base32Expected)
	{
		byte[] origin = Encoding.UTF8.GetBytes(originExpected);
		Base32Encoding encoding = hex ? Base32Encoding.Rfc4648Hex : Base32Encoding.Rfc4648;
		char[] encoded = new char[encoding.GetEncodedLength(origin.Length)];
		byte[] decoded = new byte[Base32Encoding.GetMaxDecodedLength(encoded.Length)];

		OperationStatus encodeStatus = encoding.EncodeToChars(origin, encoded, out int bytesConsumed, out int charsWritten);
		OperationStatus decodeStatus = encoding.DecodeFromChars(encoded, decoded, out int charsConsumed, out int bytesWritten);

		await Assert.That(encodeStatus).IsEqualTo(OperationStatus.Done);
		await Assert.That(decodeStatus).IsEqualTo(OperationStatus.Done);
		await Assert.That(bytesConsumed).IsEqualTo(origin.Length);
		await Assert.That(charsWritten).IsEqualTo(encoded.Length);
		await Assert.That(charsConsumed).IsEqualTo(encoded.Length);
		await Assert.That(bytesWritten).IsEqualTo(origin.Length);
		await Assert.That(encoded).IsEquivalentTo(base32Expected, CollectionOrdering.Matching);
		await Assert.That(decoded.AsMemory(0, bytesWritten)).IsEquivalentTo(origin, CollectionOrdering.Matching);
	}

	[Test]
	[MatrixDataSource]
	public async Task FourByteTailAcceptsEveryCanonicalTrailingValue([Matrix((byte)0x40, (byte)0x41, (byte)0x42, (byte)0x43)] byte lastByte, [Matrix] bool omitPadding)
	{
		Base32Encoding encoding = omitPadding ? Base32Encoding.Rfc4648.OmitPadding : Base32Encoding.Rfc4648;
		byte[] source = { 0, 0, 0, lastByte };
		char[] encodedChars = new char[encoding.GetEncodedLength(source.Length)];
		byte[] decodedChars = new byte[Base32Encoding.GetMaxDecodedLength(encodedChars.Length)];
		await Assert.That(encoding.EncodeToChars(source, encodedChars, out _, out _)).IsEqualTo(OperationStatus.Done);
		await Assert.That(encoding.DecodeFromChars(encodedChars, decodedChars, out _, out int charsWritten)).IsEqualTo(OperationStatus.Done);
		await Assert.That(decodedChars.AsMemory(0, charsWritten)).IsEquivalentTo(source, CollectionOrdering.Matching);

		byte[] encoded = new byte[encoding.GetEncodedLength(source.Length)];
		byte[] decoded = new byte[Base32Encoding.GetMaxDecodedLength(encoded.Length)];

		await Assert.That(encoding.EncodeToUtf8(source, encoded, out _, out _)).IsEqualTo(OperationStatus.Done);
		await Assert.That(encoding.DecodeFromUtf8(encoded, decoded, out _, out int written)).IsEqualTo(OperationStatus.Done);
		await Assert.That(decoded.AsMemory(0, written)).IsEquivalentTo(source, CollectionOrdering.Matching);
	}

	[Test]
	[MatrixDataSource]
	public async Task LengthsMatchIndependentEncoder([MatrixMethod<Base32Test>(nameof(SourceLengths))] int length, [Matrix] bool hex, [Matrix] bool omitPadding)
	{
		Base32Encoding encoding = hex ? Base32Encoding.Rfc4648Hex : Base32Encoding.Rfc4648;

		if (omitPadding)
		{
			encoding = encoding.OmitPadding;
		}

		byte[] source = new byte[length];

		for (int i = 0; i < source.Length; ++i)
		{
			source[i] = (byte)(i * 37 + length * 11);
		}

		char[] expected = EncodeReference(source, hex, omitPadding);
		char[] actual = new char[encoding.GetEncodedLength(source.Length)];
		await Assert.That(encoding.EncodeToChars(source, actual, out int encodeCharsConsumed, out int charsWritten)).IsEqualTo(OperationStatus.Done);
		await Assert.That(encodeCharsConsumed).IsEqualTo(source.Length);
		await Assert.That(charsWritten).IsEqualTo(expected.Length);
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);

		byte[] decodedChars = new byte[source.Length + 1];
		PrepareDestination(decodedChars);
		await Assert.That(encoding.DecodeFromChars(actual, decodedChars, out int decodeCharsConsumed, out int charsDecoded)).IsEqualTo(OperationStatus.Done);
		await Assert.That(decodeCharsConsumed).IsEqualTo(actual.Length);
		await AssertOutput(decodedChars, source, charsDecoded);

		byte[] actualUtf8 = new byte[encoding.GetEncodedLength(source.Length)];
		await Assert.That(encoding.EncodeToUtf8(source, actualUtf8, out int encodeUtf8Consumed, out int bytesWritten)).IsEqualTo(OperationStatus.Done);
		await Assert.That(encodeUtf8Consumed).IsEqualTo(source.Length);
		await Assert.That(bytesWritten).IsEqualTo(expected.Length);
		byte[] expectedUtf8 = ToByteSymbols(expected);
		await Assert.That(actualUtf8).IsEquivalentTo(expectedUtf8, CollectionOrdering.Matching);

		byte[] decodedUtf8 = new byte[source.Length + 1];
		PrepareDestination(decodedUtf8);
		await Assert.That(encoding.DecodeFromUtf8(actualUtf8, decodedUtf8, out int decodeUtf8Consumed, out int bytesDecoded)).IsEqualTo(OperationStatus.Done);
		await Assert.That(decodeUtf8Consumed).IsEqualTo(actualUtf8.Length);
		await AssertOutput(decodedUtf8, source, bytesDecoded);
	}
}
