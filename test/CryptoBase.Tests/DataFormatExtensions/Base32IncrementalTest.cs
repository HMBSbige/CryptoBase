using CryptoBase.DataFormatExtensions;
using System.Buffers;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.DataFormatExtensions;

public class Base32IncrementalTest
{
	[Test]
	public async Task IncrementalCharApisLeavePartialBlockForNextCall()
	{
		const char sentinel = (char)DestinationSentinel;
		byte[] source = "foobar"u8.ToArray();
		Base32Encoding encoding = Base32Encoding.Rfc4648;
		char[] encoded = Enumerable.Repeat(sentinel, 17).ToArray();

		OperationStatus encodeStatus = encoding.EncodeToChars(source, encoded, out int encodeConsumed, out int encodeWritten, false);
		await Assert.That(encodeStatus).IsEqualTo(OperationStatus.NeedMoreData);
		await Assert.That(encodeConsumed).IsEqualTo(5);
		await Assert.That(encodeWritten).IsEqualTo(8);
		await Assert.That(encoded.AsMemory(0, encodeWritten)).IsEquivalentTo("MZXW6YTB", CollectionOrdering.Matching);
		await Assert.That(encoded.AsMemory(encodeWritten)).All(static value => value is sentinel);

		OperationStatus finalEncodeStatus = encoding.EncodeToChars(source.AsSpan(encodeConsumed), encoded.AsSpan(encodeWritten), out int finalEncodeConsumed, out int finalEncodeWritten);
		await Assert.That(finalEncodeStatus).IsEqualTo(OperationStatus.Done);
		await Assert.That(finalEncodeConsumed).IsEqualTo(1);
		await Assert.That(finalEncodeWritten).IsEqualTo(8);
		await Assert.That(encoded.AsMemory(0, encodeWritten + finalEncodeWritten)).IsEquivalentTo("MZXW6YTBOI======", CollectionOrdering.Matching);
		await Assert.That(encoded.AsMemory(encodeWritten + finalEncodeWritten)).All(static value => value is sentinel);

		byte[] decoded = new byte[7];
		PrepareDestination(decoded);
		OperationStatus decodeStatus = encoding.DecodeFromChars("MZXW6YTBOI".AsSpan(), decoded, out int decodeConsumed, out int decodeWritten, false);
		await Assert.That(decodeStatus).IsEqualTo(OperationStatus.NeedMoreData);
		await Assert.That(decodeConsumed).IsEqualTo(8);
		await Assert.That(decodeWritten).IsEqualTo(5);
		await AssertOutput(decoded, "fooba"u8.ToArray(), decodeWritten);

		OperationStatus finalDecodeStatus = encoding.DecodeFromChars("OI======".AsSpan(), decoded.AsSpan(decodeWritten), out int finalDecodeConsumed, out int finalDecodeWritten);
		await Assert.That(finalDecodeStatus).IsEqualTo(OperationStatus.Done);
		await Assert.That(finalDecodeConsumed).IsEqualTo(8);
		await Assert.That(finalDecodeWritten).IsEqualTo(1);
		await AssertOutput(decoded, source, decodeWritten + finalDecodeWritten);
	}

	[Test]
	public async Task IncrementalUtf8ApisLeavePartialBlockForNextCall()
	{
		byte[] source = "foobar"u8.ToArray();
		Base32Encoding encoding = Base32Encoding.Rfc4648;
		byte[] encoded = new byte[17];
		PrepareDestination(encoded);

		OperationStatus encodeStatus = encoding.EncodeToUtf8(source, encoded, out int encodeConsumed, out int encodeWritten, false);
		await Assert.That(encodeStatus).IsEqualTo(OperationStatus.NeedMoreData);
		await Assert.That(encodeConsumed).IsEqualTo(5);
		await Assert.That(encodeWritten).IsEqualTo(8);
		await AssertOutput(encoded, "MZXW6YTB"u8.ToArray(), encodeWritten);

		OperationStatus finalEncodeStatus = encoding.EncodeToUtf8(source.AsSpan(encodeConsumed), encoded.AsSpan(encodeWritten), out int finalEncodeConsumed, out int finalEncodeWritten);
		await Assert.That(finalEncodeStatus).IsEqualTo(OperationStatus.Done);
		await Assert.That(finalEncodeConsumed).IsEqualTo(1);
		await Assert.That(finalEncodeWritten).IsEqualTo(8);
		await AssertOutput(encoded, "MZXW6YTBOI======"u8.ToArray(), encodeWritten + finalEncodeWritten);

		byte[] decoded = new byte[7];
		PrepareDestination(decoded);
		OperationStatus decodeStatus = encoding.DecodeFromUtf8(encoded.AsSpan(0, 10), decoded, out int decodeConsumed, out int decodeWritten, false);
		await Assert.That(decodeStatus).IsEqualTo(OperationStatus.NeedMoreData);
		await Assert.That(decodeConsumed).IsEqualTo(8);
		await Assert.That(decodeWritten).IsEqualTo(5);
		await AssertOutput(decoded, "fooba"u8.ToArray(), decodeWritten);

		OperationStatus finalDecodeStatus = encoding.DecodeFromUtf8("OI======"u8, decoded.AsSpan(decodeWritten), out int finalDecodeConsumed, out int finalDecodeWritten);
		await Assert.That(finalDecodeStatus).IsEqualTo(OperationStatus.Done);
		await Assert.That(finalDecodeConsumed).IsEqualTo(8);
		await Assert.That(finalDecodeWritten).IsEqualTo(1);
		await AssertOutput(decoded, source, decodeWritten + finalDecodeWritten);
	}

	[Test]
	public async Task IncrementalApisCompleteWholeBlocks()
	{
		byte[] source = "fooba"u8.ToArray();
		char[] encodedChars = new char[8];
		byte[] encodedUtf8 = new byte[8];
		byte[] decodedChars = new byte[5];
		byte[] decodedUtf8 = new byte[5];

		OperationStatus encodeCharStatus = Base32Encoding.Rfc4648.EncodeToChars(source, encodedChars, out int encodeCharsConsumed, out int charsWritten, false);
		OperationStatus encodeUtf8Status = Base32Encoding.Rfc4648.EncodeToUtf8(source, encodedUtf8, out int encodeBytesConsumed, out int bytesWritten, false);
		OperationStatus decodeCharStatus = Base32Encoding.Rfc4648.DecodeFromChars(encodedChars, decodedChars, out int decodeCharsConsumed, out int charsDecoded, false);
		OperationStatus decodeUtf8Status = Base32Encoding.Rfc4648.DecodeFromUtf8(encodedUtf8, decodedUtf8, out int decodeBytesConsumed, out int bytesDecoded, false);

		await Assert.That(encodeCharStatus).IsEqualTo(OperationStatus.Done);
		await Assert.That(encodeUtf8Status).IsEqualTo(OperationStatus.Done);
		await Assert.That(decodeCharStatus).IsEqualTo(OperationStatus.Done);
		await Assert.That(decodeUtf8Status).IsEqualTo(OperationStatus.Done);
		await Assert.That(encodeCharsConsumed).IsEqualTo(source.Length);
		await Assert.That(encodeBytesConsumed).IsEqualTo(source.Length);
		await Assert.That(charsWritten).IsEqualTo(8);
		await Assert.That(bytesWritten).IsEqualTo(8);
		await Assert.That(decodeCharsConsumed).IsEqualTo(8);
		await Assert.That(decodeBytesConsumed).IsEqualTo(8);
		await Assert.That(charsDecoded).IsEqualTo(source.Length);
		await Assert.That(bytesDecoded).IsEqualTo(source.Length);
		await Assert.That(encodedChars).IsEquivalentTo("MZXW6YTB", CollectionOrdering.Matching);
		await Assert.That(encodedUtf8).IsEquivalentTo("MZXW6YTB"u8.ToArray(), CollectionOrdering.Matching);
		await Assert.That(decodedChars).IsEquivalentTo(source, CollectionOrdering.Matching);
		await Assert.That(decodedUtf8).IsEquivalentTo(source, CollectionOrdering.Matching);
	}
}
