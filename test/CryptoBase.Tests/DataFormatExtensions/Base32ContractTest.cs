using CryptoBase.DataFormatExtensions;
using System.Buffers;
using static CryptoBase.Tests.DataFormatExtensions.Base32TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.DataFormatExtensions;

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
	public async Task InvalidInputReturnsInvalidData(string encoded)
	{
		byte[] encodedBytes = ToByteSymbols(encoded);
		byte[] charDestination = Enumerable.Repeat(DestinationSentinel, 8).ToArray();
		byte[] utf8Destination = Enumerable.Repeat(DestinationSentinel, 8).ToArray();
		OperationStatus charStatus = Base32Encoding.Rfc4648.DecodeFromChars(encoded.AsSpan(), charDestination, out int charsConsumed, out int charsWritten);
		OperationStatus utf8Status = Base32Encoding.Rfc4648.DecodeFromUtf8(encodedBytes, utf8Destination, out int bytesConsumed, out int bytesWritten);

		await Assert.That(charStatus).IsEqualTo(OperationStatus.InvalidData);
		await Assert.That(utf8Status).IsEqualTo(OperationStatus.InvalidData);
		await Assert.That(charsConsumed).IsZero();
		await Assert.That(charsWritten).IsZero();
		await Assert.That(bytesConsumed).IsZero();
		await Assert.That(bytesWritten).IsZero();
		await Assert.That(charDestination).All(static value => value is DestinationSentinel);
		await Assert.That(utf8Destination).All(static value => value is DestinationSentinel);
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
		string alphabet = customAlphabet ? "abcdefghijklmnopqrstuvwxyz234567" : "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
		Base32Encoding encoding = customAlphabet ? Base32Encoding.Create(alphabet) : Base32Encoding.Rfc4648;
		byte[] encodeSource = Enumerable.Range(0, 20).Select(static value => (byte)(value * 37 + 11)).ToArray();
		byte[] decodeSource = Enumerable.Range(0, 80).Select(static value => (byte)(value * 37 + 11)).ToArray();

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
	public async Task PaddingPolicyAndRawSymbolCountsAreEnforced(bool omitPadding, string encoded)
	{
		Base32Encoding encoding = omitPadding ? Base32Encoding.Rfc4648.OmitPadding : Base32Encoding.Rfc4648;
		byte[] destinationChars = Enumerable.Repeat(DestinationSentinel, 8).ToArray();
		byte[] destinationUtf8 = Enumerable.Repeat(DestinationSentinel, 8).ToArray();
		OperationStatus charStatus = encoding.DecodeFromChars(encoded, destinationChars, out int charsConsumed, out int charsWritten);
		OperationStatus utf8Status = encoding.DecodeFromUtf8(ToByteSymbols(encoded), destinationUtf8, out int bytesConsumed, out int bytesWritten);

		await Assert.That(charStatus).IsEqualTo(OperationStatus.InvalidData);
		await Assert.That(utf8Status).IsEqualTo(OperationStatus.InvalidData);
		await Assert.That(charsConsumed).IsZero();
		await Assert.That(charsWritten).IsZero();
		await Assert.That(bytesConsumed).IsZero();
		await Assert.That(bytesWritten).IsZero();
		await Assert.That(destinationChars).All(static value => value is DestinationSentinel);
		await Assert.That(destinationUtf8).All(static value => value is DestinationSentinel);
	}

	[Test]
	[MatrixDataSource]
	public async Task NonCanonicalTrailingBitsAreRejectedForEveryShortTail([Matrix(1, 2, 3, 4)] int sourceLength, [Matrix] bool omitPadding, [Matrix] bool hex)
	{
		Base32Encoding encoding = hex ? Base32Encoding.Rfc4648Hex : Base32Encoding.Rfc4648;

		if (omitPadding)
		{
			encoding = encoding.OmitPadding;
		}

		string alphabet = hex ? "0123456789ABCDEFGHIJKLMNOPQRSTUV" : "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
		char[] encoded = EncodeReference(new byte[sourceLength], hex, omitPadding);
		int rawSymbolCount = (sourceLength * 8 + 4) / 5;
		int unusedBits = rawSymbolCount * 5 - sourceLength * 8;
		byte[] destinationChars = new byte[sourceLength + 1];
		byte[] destinationUtf8 = new byte[sourceLength + 1];

		for (int trailingValue = 1; trailingValue < 1 << unusedBits; ++trailingValue)
		{
			encoded[rawSymbolCount - 1] = alphabet[trailingValue];
			byte[] encodedUtf8 = ToByteSymbols(encoded);
			PrepareDestination(destinationChars);
			PrepareDestination(destinationUtf8);
			OperationStatus charStatus = encoding.DecodeFromChars(encoded, destinationChars, out int charsConsumed, out int charsWritten);
			OperationStatus utf8Status = encoding.DecodeFromUtf8(encodedUtf8, destinationUtf8, out int bytesConsumed, out int bytesWritten);

			await Assert.That(charStatus).IsEqualTo(OperationStatus.InvalidData);
			await Assert.That(utf8Status).IsEqualTo(OperationStatus.InvalidData);
			await Assert.That(charsConsumed).IsZero();
			await Assert.That(charsWritten).IsZero();
			await Assert.That(bytesConsumed).IsZero();
			await Assert.That(bytesWritten).IsZero();
			await Assert.That(destinationChars).All(static value => value is DestinationSentinel);
			await Assert.That(destinationUtf8).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	public async Task InvalidLastSymbolReportsTheValidPrefix()
	{
		byte[] destinationChars = Enumerable.Repeat(DestinationSentinel, 1).ToArray();
		byte[] destinationUtf8 = Enumerable.Repeat(DestinationSentinel, 1).ToArray();
		OperationStatus charStatus = Base32Encoding.Rfc4648.OmitPadding.DecodeFromChars("M!", destinationChars, out int charsConsumed, out int charsWritten);
		OperationStatus utf8Status = Base32Encoding.Rfc4648.OmitPadding.DecodeFromUtf8("M!"u8, destinationUtf8, out int bytesConsumed, out int bytesWritten);

		await Assert.That(charStatus).IsEqualTo(OperationStatus.InvalidData);
		await Assert.That(utf8Status).IsEqualTo(OperationStatus.InvalidData);
		await Assert.That(charsConsumed).IsEqualTo(1);
		await Assert.That(charsWritten).IsZero();
		await Assert.That(bytesConsumed).IsEqualTo(1);
		await Assert.That(bytesWritten).IsZero();
		await Assert.That(destinationChars).All(static value => value is DestinationSentinel);
		await Assert.That(destinationUtf8).All(static value => value is DestinationSentinel);
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
}
