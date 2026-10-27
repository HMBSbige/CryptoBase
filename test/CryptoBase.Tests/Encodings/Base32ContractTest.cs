using CryptoBase.Encodings;
using System.Buffers;
using static CryptoBase.Tests.Encodings.Base32TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Encodings;

public class Base32ContractTest
{
	[Test]
	[Arguments("!")]
	[Arguments("a")]
	[Arguments("\u007f")]
	[Arguments("\u0080")]
	[Arguments("!Y======")]
	[Arguments("aY======")]
	[Arguments("\u007fY======")]
	[Arguments("\u0080Y======")]
	[Arguments("M=Y")]
	[Arguments("M=AAAAAA")]
	[Arguments("MZ======")]
	[Arguments("=M======")]
	public Task InvalidInputReturnsInvalidData(string encoded)
	{
		return AssertInvalidWithoutWriting(Base32Encoding.Rfc4648, encoded, 8);
	}

	[Test]
	[Arguments(false)]
	[Arguments(true)]
	public Task InvalidFirstSymbolInLongInputDoesNotWrite(bool hex)
	{
		Base32Encoding encoding = Rfc4648Encoding(hex);
		byte[] source = CreateDeterministicSource(1040);
		char[] encoded = EncodeReference(source, hex, false);
		encoded[0] = '!';

		return AssertInvalidWithoutWriting(encoding, new string(encoded), source.Length);
	}

	[Test]
	[MatrixDataSource]
	public async Task Utf8InvalidSymbolReportsProcessedPrefix([Matrix(15, 16, 31, 32, 63, 64, 127, 128, 255, 327)] int invalidOffset)
	{
		byte[] source = CreateDeterministicSource(205);
		byte[] encoded = ToByteSymbols(EncodeReference(source, false, false));
		encoded[invalidOffset] = (byte)'!';
		byte[] destination = new byte[source.Length];
		PrepareDestination(destination);

		OperationStatus status = Base32Encoding.Rfc4648.DecodeFromUtf8(encoded, destination, out int consumed, out int written);

		byte[] expected = source.AsSpan().Slice(0, invalidOffset / 8 * 5).ToArray();
		await Assert.That(status).IsEqualTo(OperationStatus.InvalidData);
		await Assert.That(consumed).IsEqualTo(invalidOffset / 8 * 8);
		await AssertOutput(destination, expected, written);
	}

	[Test]
	[MatrixDataSource]
	public async Task CharInvalidSymbolReportsProcessedPrefix([Matrix('!', '\u0080', '\u0100')] char invalidSymbol, [Matrix(15, 16, 31, 32, 63, 64, 127, 128, 255, 327)] int invalidOffset)
	{
		byte[] source = CreateDeterministicSource(205);
		char[] encoded = EncodeReference(source, false, false);
		encoded[invalidOffset] = invalidSymbol;
		byte[] destination = new byte[source.Length];
		PrepareDestination(destination);

		OperationStatus status = Base32Encoding.Rfc4648.DecodeFromChars(encoded, destination, out int consumed, out int written);

		byte[] expected = source.AsSpan().Slice(0, invalidOffset / 8 * 5).ToArray();
		await Assert.That(status).IsEqualTo(OperationStatus.InvalidData);
		await Assert.That(consumed).IsEqualTo(invalidOffset / 8 * 8);
		await AssertOutput(destination, expected, written);
	}

	[Test]
	[MatrixDataSource]
	public async Task EveryInvalidAsciiSymbolIsRejectedAtVectorLengths([Matrix(32, 40, 56, 64, 72, 128)] int symbolCount, [Matrix] bool hex)
	{
		// The lengths reach the 256-bit and 512-bit decoders; '=' is skipped because its validity depends on its position.
		Base32Encoding encoding = Rfc4648Encoding(hex);
		string alphabet = Rfc4648Alphabet(hex);
		byte[] source = CreateDeterministicSource(symbolCount / 8 * 5);
		char[] valid = EncodeReference(source, hex, false);
		int[] positions = [0, 7, 31, symbolCount - 1];
		char[] chars = new char[symbolCount];
		byte[] charDestination = new byte[source.Length];
		byte[] utf8Destination = new byte[source.Length];
		List<string> failures = [];

		for (char symbol = (char)0; symbol < (char)0x80; ++symbol)
		{
			if (symbol is '=' || alphabet.Contains(symbol))
			{
				continue;
			}

			foreach (int position in positions.Distinct())
			{
				valid.CopyTo(chars, 0);
				chars[position] = symbol;
				PrepareDestination(charDestination);
				PrepareDestination(utf8Destination);
				OperationStatus charStatus = encoding.DecodeFromChars(chars, charDestination, out int charsConsumed, out int charsWritten);
				OperationStatus utf8Status = encoding.DecodeFromUtf8(ToByteSymbols(chars), utf8Destination, out int bytesConsumed, out int bytesWritten);
				int expectedConsumed = position / 8 * 8;
				int expectedWritten = position / 8 * 5;

				if (charStatus is not OperationStatus.InvalidData || charsConsumed != expectedConsumed || charsWritten != expectedWritten || !IsPrefixFollowedBySentinel(charDestination, source, expectedWritten)
					|| utf8Status is not OperationStatus.InvalidData || bytesConsumed != expectedConsumed || bytesWritten != expectedWritten || !IsPrefixFollowedBySentinel(utf8Destination, source, expectedWritten))
				{
					failures.Add($"U+{(int)symbol:X4} at {position}: chars {charStatus}/{charsConsumed}/{charsWritten}, utf8 {utf8Status}/{bytesConsumed}/{bytesWritten}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task DestinationTooSmallDoesNotWrite()
	{
		byte[] source = "foo"u8.ToArray();
		char[] chars = Enumerable.Repeat('x', 4).ToArray();
		byte[] encoded = Enumerable.Repeat((byte)0xcc, 4).ToArray();
		byte[] decodedChars = Enumerable.Repeat((byte)0xcc, 2).ToArray();
		byte[] decodedUtf8 = Enumerable.Repeat((byte)0xcc, 2).ToArray();

		OperationStatus charStatus = Base32Encoding.Rfc4648.EncodeToChars(source, chars, out int charConsumed, out int charWritten);
		OperationStatus utf8Status = Base32Encoding.Rfc4648.EncodeToUtf8(source, encoded, out int utf8Consumed, out int utf8Written);
		OperationStatus decodeCharStatus = Base32Encoding.Rfc4648.DecodeFromChars("MZXW6===".AsSpan(), decodedChars, out int decodeCharsConsumed, out int decodedCharsWritten);
		OperationStatus decodeUtf8Status = Base32Encoding.Rfc4648.DecodeFromUtf8("MZXW6==="u8, decodedUtf8, out int decodeBytesConsumed, out int decodedBytesWritten);

		await Assert.That(charStatus).IsEqualTo(OperationStatus.DestinationTooSmall);
		await Assert.That(utf8Status).IsEqualTo(OperationStatus.DestinationTooSmall);
		await Assert.That(decodeCharStatus).IsEqualTo(OperationStatus.DestinationTooSmall);
		await Assert.That(decodeUtf8Status).IsEqualTo(OperationStatus.DestinationTooSmall);
		await Assert.That(charConsumed).IsZero();
		await Assert.That(charWritten).IsZero();
		await Assert.That(utf8Consumed).IsZero();
		await Assert.That(utf8Written).IsZero();
		await Assert.That(decodeCharsConsumed).IsZero();
		await Assert.That(decodedCharsWritten).IsZero();
		await Assert.That(decodeBytesConsumed).IsZero();
		await Assert.That(decodedBytesWritten).IsZero();
		await Assert.That(chars).All(static value => value is 'x');
		await Assert.That(encoded).All(static value => value is 0xcc);
		await Assert.That(decodedChars).All(static value => value is 0xcc);
		await Assert.That(decodedUtf8).All(static value => value is 0xcc);
	}

	[Test]
	public async Task DestinationTooSmallReportsProcessedPrefix()
	{
		byte[] source = Enumerable.Range(0, 10).Select(static value => (byte)value).ToArray();
		Base32Encoding encoding = Base32Encoding.Rfc4648;
		char[] encodedChars = new char[8];
		byte[] encodedUtf8 = new byte[8];

		OperationStatus encodeCharStatus = encoding.EncodeToChars(source, encodedChars, out int encodeCharsConsumed, out int charsWritten);
		OperationStatus encodeUtf8Status = encoding.EncodeToUtf8(source, encodedUtf8, out int encodeBytesConsumed, out int bytesWritten);
		await Assert.That(encodeCharStatus).IsEqualTo(OperationStatus.DestinationTooSmall);
		await Assert.That(encodeUtf8Status).IsEqualTo(OperationStatus.DestinationTooSmall);
		await Assert.That(encodeCharsConsumed).IsEqualTo(5);
		await Assert.That(encodeBytesConsumed).IsEqualTo(5);
		await Assert.That(charsWritten).IsEqualTo(8);
		await Assert.That(bytesWritten).IsEqualTo(8);

		char[] expected = new char[encoding.GetEncodedLength(source.Length)];
		await Assert.That(encoding.EncodeToChars(source, expected, out _, out _)).IsEqualTo(OperationStatus.Done);
		byte[] expectedUtf8 = ToByteSymbols(expected);
		await Assert.That(expected.AsMemory(0, 8)).IsEquivalentTo(encodedChars, CollectionOrdering.Matching);
		await Assert.That(expectedUtf8.AsMemory(0, 8)).IsEquivalentTo(encodedUtf8, CollectionOrdering.Matching);

		byte[] decodedChars = new byte[5];
		byte[] decodedUtf8 = new byte[5];
		OperationStatus decodeCharStatus = encoding.DecodeFromChars(expected, decodedChars, out int decodeCharsConsumed, out int charsDecoded);
		OperationStatus decodeUtf8Status = encoding.DecodeFromUtf8(expectedUtf8, decodedUtf8, out int decodeBytesConsumed, out int bytesDecoded);
		await Assert.That(decodeCharStatus).IsEqualTo(OperationStatus.DestinationTooSmall);
		await Assert.That(decodeUtf8Status).IsEqualTo(OperationStatus.DestinationTooSmall);
		await Assert.That(decodeCharsConsumed).IsEqualTo(8);
		await Assert.That(decodeBytesConsumed).IsEqualTo(8);
		await Assert.That(charsDecoded).IsEqualTo(5);
		await Assert.That(bytesDecoded).IsEqualTo(5);
		await Assert.That(source.AsMemory(0, 5)).IsEquivalentTo(decodedChars, CollectionOrdering.Matching);
		await Assert.That(source.AsMemory(0, 5)).IsEquivalentTo(decodedUtf8, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(false)]
	[Arguments(true)]
	public async Task VectorBlockDestinationTooSmallReportsProcessedPrefix(bool customAlphabet)
	{
		string alphabet = customAlphabet ? LowercaseAlphabet : Rfc4648Alphabet(false);
		Base32Encoding encoding = customAlphabet ? Base32Encoding.Create(alphabet) : Base32Encoding.Rfc4648;
		byte[] encodeSource = CreatePatternSource(20, 11);
		byte[] decodeSource = CreatePatternSource(80, 11);

		char[] expectedChars = EncodeReference(encodeSource, alphabet, '=', false);
		byte[] expectedUtf8 = ToByteSymbols(expectedChars);
		char[] encodedChars = new char[16];
		byte[] encodedUtf8 = new byte[16];

		OperationStatus encodeCharStatus = encoding.EncodeToChars(encodeSource, encodedChars, out int encodeCharsConsumed, out int charsWritten);
		OperationStatus encodeUtf8Status = encoding.EncodeToUtf8(encodeSource, encodedUtf8, out int encodeBytesConsumed, out int bytesWritten);

		await Assert.That(encodeCharStatus).IsEqualTo(OperationStatus.DestinationTooSmall);
		await Assert.That(encodeUtf8Status).IsEqualTo(OperationStatus.DestinationTooSmall);
		await Assert.That(encodeCharsConsumed).IsEqualTo(10);
		await Assert.That(encodeBytesConsumed).IsEqualTo(10);
		await Assert.That(charsWritten).IsEqualTo(16);
		await Assert.That(bytesWritten).IsEqualTo(16);
		await Assert.That(expectedChars.AsMemory(0, 16)).IsEquivalentTo(encodedChars, CollectionOrdering.Matching);
		await Assert.That(expectedUtf8.AsMemory(0, 16)).IsEquivalentTo(encodedUtf8, CollectionOrdering.Matching);

		char[] fullEncodedChars = EncodeReference(decodeSource, alphabet, '=', false);
		byte[] fullEncodedUtf8 = ToByteSymbols(fullEncodedChars);
		byte[] decodedChars = new byte[40];
		byte[] decodedUtf8 = new byte[40];
		OperationStatus decodeCharStatus = encoding.DecodeFromChars(fullEncodedChars, decodedChars, out int decodeCharsConsumed, out int charsDecoded);
		OperationStatus decodeUtf8Status = encoding.DecodeFromUtf8(fullEncodedUtf8, decodedUtf8, out int decodeBytesConsumed, out int bytesDecoded);

		await Assert.That(decodeCharStatus).IsEqualTo(OperationStatus.DestinationTooSmall);
		await Assert.That(decodeUtf8Status).IsEqualTo(OperationStatus.DestinationTooSmall);
		await Assert.That(decodeCharsConsumed).IsEqualTo(64);
		await Assert.That(decodeBytesConsumed).IsEqualTo(64);
		await Assert.That(charsDecoded).IsEqualTo(40);
		await Assert.That(bytesDecoded).IsEqualTo(40);
		await Assert.That(decodeSource.AsMemory(0, 40)).IsEquivalentTo(decodedChars, CollectionOrdering.Matching);
		await Assert.That(decodeSource.AsMemory(0, 40)).IsEquivalentTo(decodedUtf8, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(false, "MY")]
	[Arguments(true, "MY======")]
	[Arguments(true, "M")]
	[Arguments(true, "MZX")]
	[Arguments(true, "MZXW6Y")]
	public Task PaddingPolicyAndRawSymbolCountsAreEnforced(bool omitPadding, string encoded)
	{
		Base32Encoding encoding = Rfc4648Encoding(false, omitPadding);
		return AssertInvalidWithoutWriting(encoding, encoded, 8);
	}

	[Test]
	[MatrixDataSource]
	public async Task NonCanonicalTrailingBitsAreRejectedForEveryShortTail([Matrix(1, 2, 3, 4)] int sourceLength, [Matrix] bool omitPadding, [Matrix] bool hex)
	{
		Base32Encoding encoding = Rfc4648Encoding(hex, omitPadding);

		string alphabet = Rfc4648Alphabet(hex);
		char[] encoded = EncodeReference(new byte[sourceLength], hex, omitPadding);
		int rawSymbolCount = (sourceLength * 8 + 4) / 5;
		int unusedBits = rawSymbolCount * 5 - sourceLength * 8;

		for (int trailingValue = 1; trailingValue < 1 << unusedBits; ++trailingValue)
		{
			encoded[rawSymbolCount - 1] = alphabet[trailingValue];
			await AssertInvalidWithoutWriting(encoding, new string(encoded), sourceLength + 1);
		}
	}

	[Test]
	public Task InvalidLastSymbolReportsTheValidPrefix()
	{
		return AssertInvalidWithoutWriting(Base32Encoding.Rfc4648.OmitPadding, "M!", 1, expectedConsumed: 1);
	}

	[Test]
	public async Task LengthMethodsValidateTheirArguments()
	{
		Base32Encoding padded = Base32Encoding.Rfc4648;
		Base32Encoding unpadded = padded.OmitPadding;

		await Assert.That(() => padded.GetEncodedLength(-1)).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(padded.GetEncodedLength(1_342_177_274)).IsEqualTo(2_147_483_640);
		await Assert.That(padded.GetEncodedLength(1_342_177_275)).IsEqualTo(2_147_483_640);
		await Assert.That(() => padded.GetEncodedLength(1_342_177_276)).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(() => padded.GetEncodedLength(int.MaxValue)).ThrowsExactly<ArgumentOutOfRangeException>();

		await Assert.That(() => unpadded.GetEncodedLength(-1)).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(unpadded.GetEncodedLength(1_342_177_278)).IsEqualTo(2_147_483_645);
		await Assert.That(unpadded.GetEncodedLength(1_342_177_279)).IsEqualTo(int.MaxValue);
		await Assert.That(() => unpadded.GetEncodedLength(1_342_177_280)).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(() => unpadded.GetEncodedLength(int.MaxValue)).ThrowsExactly<ArgumentOutOfRangeException>();

		await Assert.That(() => Base32Encoding.GetMaxDecodedLength(-1)).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(Base32Encoding.GetMaxDecodedLength(int.MaxValue)).IsEqualTo(1_342_177_279);
	}

	private static async Task AssertInvalidWithoutWriting(Base32Encoding encoding, string encoded, int destinationLength, int expectedConsumed = 0)
	{
		byte[] charDestination = new byte[destinationLength];
		byte[] utf8Destination = new byte[destinationLength];
		PrepareDestination(charDestination);
		PrepareDestination(utf8Destination);
		OperationStatus charStatus = encoding.DecodeFromChars(encoded, charDestination, out int charsConsumed, out int charsWritten);
		OperationStatus utf8Status = encoding.DecodeFromUtf8(ToByteSymbols(encoded), utf8Destination, out int bytesConsumed, out int bytesWritten);

		await Assert.That(charStatus).IsEqualTo(OperationStatus.InvalidData);
		await Assert.That(utf8Status).IsEqualTo(OperationStatus.InvalidData);
		await Assert.That(charsConsumed).IsEqualTo(expectedConsumed);
		await Assert.That(charsWritten).IsZero();
		await Assert.That(bytesConsumed).IsEqualTo(expectedConsumed);
		await Assert.That(bytesWritten).IsZero();
		await Assert.That(charDestination).All(static value => value is DestinationSentinel);
		await Assert.That(utf8Destination).All(static value => value is DestinationSentinel);
	}

	private static bool IsPrefixFollowedBySentinel(byte[] destination, byte[] source, int length)
	{
		return destination.AsSpan(0, length).SequenceEqual(source.AsSpan(0, length)) && !destination.AsSpan(length).ContainsAnyExcept(DestinationSentinel);
	}
}
