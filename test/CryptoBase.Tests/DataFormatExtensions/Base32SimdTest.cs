using CryptoBase.DataFormatExtensions;
using System.Buffers;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using System.Text;
using static CryptoBase.Tests.DataFormatExtensions.Base32TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.DataFormatExtensions;

public class Base32SimdTest
{
	public static IEnumerable<int> VectorBoundaryLengths()
	{
		return [10, 13, 20, 23, 40, 43, 50, 80, 120, 160, 200, 205];
	}

	public static IEnumerable<int> LateInvalidOffsets()
	{
		return [15, 16, 31, 32, 63, 64, 127, 128, 255, 327];
	}

	public static IEnumerable<string> SupportedPaths()
	{
		yield return nameof(Base32SimdPath.Scalar);

		if (Ssse3.IsSupported)
		{
			yield return nameof(Base32SimdPath.Ssse3);
		}

		if (Avx2.IsSupported)
		{
			yield return nameof(Base32SimdPath.Avx2);
		}

		if (Avx512BW.IsSupported)
		{
			yield return nameof(Base32SimdPath.Avx512Bw);
		}

		if (Avx512Vbmi.IsSupported && Avx512BW.IsSupported)
		{
			yield return nameof(Base32SimdPath.Avx512Vbmi);
		}

		if (Avx512Vbmi.VL.IsSupported && Avx512BW.VL.IsSupported)
		{
			yield return nameof(Base32SimdPath.Avx512VbmiVl256);
			yield return nameof(Base32SimdPath.Avx512VbmiVl128);
		}

		if (AdvSimd.IsSupported)
		{
			yield return nameof(Base32SimdPath.AdvSimd);
		}
	}

	public static IEnumerable<string> SupportedSimdPaths()
	{
		return SupportedPaths()
			.Where(static path => path is not nameof(Base32SimdPath.Scalar))
			.DefaultIfEmpty(nameof(Base32SimdPath.Scalar));
	}

	[Test]
	[MatrixDataSource]
	public async Task Utf8PathMatchesIndependentEncoder([MatrixMethod<Base32SimdTest>(nameof(SupportedPaths))] string pathName, [Matrix] bool hex)
	{
		Base32Encoding encoding = hex ? Base32Encoding.Rfc4648Hex : Base32Encoding.Rfc4648;
		const int sourceLength = 1040;
		Base32SimdPath path = Enum.Parse<Base32SimdPath>(pathName);
		byte[] source = new byte[sourceLength];

		for (int i = 0; i < source.Length; ++i)
		{
			source[i] = (byte)(i * 37 + 11);
		}

		char[] expectedChars = EncodeReference(source, hex, false);
		byte[] expected = Encoding.ASCII.GetBytes(expectedChars);
		byte[] encoded = new byte[expected.Length];
		byte[] decoded = new byte[source.Length];

		int encodePathConsumed;

		if (path is Base32SimdPath.Scalar)
		{
			OperationStatus status = encoding.EncodeToUtf8Path(source, encoded, out int consumed, out int written, true, path);
			await Assert.That(status).IsEqualTo(OperationStatus.Done);
			await Assert.That(consumed).IsEqualTo(source.Length);
			await Assert.That(written).IsEqualTo(expected.Length);
			encodePathConsumed = 0;
		}
		else
		{
			encodePathConsumed = encoding.EncodeUtf8BlocksPath(source, encoded, path);
		}

		int decodePathConsumed = encoding.DecodeUtf8BlocksPath(expected, decoded, path);
		await Assert.That(encoded).IsEquivalentTo(expected, CollectionOrdering.Matching);
		await Assert.That(decoded).IsEquivalentTo(source, CollectionOrdering.Matching);
		await Assert.That(encodePathConsumed).IsEqualTo(path is Base32SimdPath.Scalar ? 0 : source.Length);
		await Assert.That(decodePathConsumed).IsEqualTo(expected.Length);

		byte[] invalid = (byte[])expected.Clone();
		invalid[0] = (byte)'!';
		decoded.AsSpan().Fill(DestinationSentinel);
		int invalidConsumed = encoding.DecodeUtf8BlocksPath(invalid, decoded, path);
		await Assert.That(invalidConsumed).IsZero();
		await Assert.That(decoded).All(static value => value is DestinationSentinel);
	}

	[Test]
	[MatrixDataSource]
	public async Task Utf8PathsHandleVectorBoundaries([MatrixMethod<Base32SimdTest>(nameof(SupportedPaths))] string pathName, [MatrixMethod<Base32SimdTest>(nameof(VectorBoundaryLengths))] int sourceLength, [Matrix] bool hex)
	{
		Base32Encoding encoding = hex ? Base32Encoding.Rfc4648Hex : Base32Encoding.Rfc4648;
		Base32SimdPath path = Enum.Parse<Base32SimdPath>(pathName);

		byte[] source = new byte[sourceLength];

		for (int i = 0; i < source.Length; ++i)
		{
			source[i] = (byte)(i * 37 + sourceLength * 11);
		}

		byte[] expected = ToByteSymbols(EncodeReference(source, hex, false));
		byte[] encoded = new byte[expected.Length];
		byte[] decoded = new byte[source.Length];

		OperationStatus encodeStatus = encoding.EncodeToUtf8Path(source, encoded, out int encodeConsumed, out int encodeWritten, true, path);
		OperationStatus decodeStatus = encoding.DecodeFromUtf8Path(encoded, decoded, out int decodeConsumed, out int decodeWritten, true, path);

		await Assert.That(encodeStatus).IsEqualTo(OperationStatus.Done);
		await Assert.That(decodeStatus).IsEqualTo(OperationStatus.Done);
		await Assert.That(encodeConsumed).IsEqualTo(source.Length);
		await Assert.That(encodeWritten).IsEqualTo(expected.Length);
		await Assert.That(decodeConsumed).IsEqualTo(expected.Length);
		await Assert.That(decodeWritten).IsEqualTo(source.Length);
		await Assert.That(encoded).IsEquivalentTo(expected, CollectionOrdering.Matching);
		await Assert.That(decoded).IsEquivalentTo(source, CollectionOrdering.Matching);
	}

	[Test]
	[MatrixDataSource]
	public async Task Utf8SimdPathsReportLateInvalidDataLikeScalar([MatrixMethod<Base32SimdTest>(nameof(SupportedSimdPaths))] string pathName, [MatrixMethod<Base32SimdTest>(nameof(LateInvalidOffsets))] int invalidOffset)
	{
		const int sourceLength = 205;
		Base32SimdPath path = Enum.Parse<Base32SimdPath>(pathName);
		Skip.When(path is Base32SimdPath.Scalar, "No supported SIMD instruction set is available.");
		byte[] source = new byte[sourceLength];

		for (int i = 0; i < source.Length; ++i)
		{
			source[i] = (byte)(i * 37 + 11);
		}

		byte[] encoded = ToByteSymbols(EncodeReference(source, false, false));

		encoded[invalidOffset] = (byte)'!';
		byte[] scalarDestination = Enumerable.Repeat(DestinationSentinel, source.Length).ToArray();
		byte[] simdDestination = Enumerable.Repeat(DestinationSentinel, source.Length).ToArray();

		OperationStatus scalarStatus = Base32Encoding.Rfc4648.DecodeFromUtf8Path(encoded, scalarDestination, out int scalarConsumed, out int scalarWritten, true, Base32SimdPath.Scalar);
		OperationStatus simdStatus = Base32Encoding.Rfc4648.DecodeFromUtf8Path(encoded, simdDestination, out int simdConsumed, out int simdWritten, true, path);

		int expectedConsumed = invalidOffset / 8 * 8;
		byte[] expected = source.AsSpan().Slice(0, invalidOffset / 8 * 5).ToArray();
		await Assert.That(scalarStatus).IsEqualTo(OperationStatus.InvalidData);
		await Assert.That(simdStatus).IsEqualTo(OperationStatus.InvalidData);
		await Assert.That(scalarConsumed).IsEqualTo(expectedConsumed);
		await Assert.That(simdConsumed).IsEqualTo(expectedConsumed);
		await AssertOutput(scalarDestination, expected, scalarWritten);
		await AssertOutput(simdDestination, expected, simdWritten);
	}

	[Test]
	[MatrixDataSource]
	public async Task CharPathMatchesIndependentEncoder([MatrixMethod<Base32SimdTest>(nameof(SupportedPaths))] string pathName, [Matrix] bool hex)
	{
		Base32Encoding encoding = hex ? Base32Encoding.Rfc4648Hex : Base32Encoding.Rfc4648;
		const int sourceLength = 1040;
		Base32SimdPath path = Enum.Parse<Base32SimdPath>(pathName);
		byte[] source = new byte[sourceLength];

		for (int i = 0; i < source.Length; ++i)
		{
			source[i] = (byte)(i * 37 + 11);
		}

		char[] expected = EncodeReference(source, hex, false);
		char[] encoded = new char[expected.Length];
		byte[] decoded = new byte[source.Length];

		int encodePathConsumed;

		if (path is Base32SimdPath.Scalar)
		{
			OperationStatus status = encoding.EncodeToCharsPath(source, encoded, out int consumed, out int written, true, path);
			await Assert.That(status).IsEqualTo(OperationStatus.Done);
			await Assert.That(consumed).IsEqualTo(source.Length);
			await Assert.That(written).IsEqualTo(expected.Length);
			encodePathConsumed = 0;
		}
		else
		{
			encodePathConsumed = encoding.EncodeCharsBlocksPath(source, encoded, path);
		}

		int decodePathConsumed = encoding.DecodeCharsBlocksPath(expected, decoded, path);
		await Assert.That(encoded).IsEquivalentTo(expected, CollectionOrdering.Matching);
		await Assert.That(decoded).IsEquivalentTo(source, CollectionOrdering.Matching);
		await Assert.That(encodePathConsumed).IsEqualTo(path is Base32SimdPath.Scalar ? 0 : source.Length);
		await Assert.That(decodePathConsumed).IsEqualTo(expected.Length);
	}

	[Test]
	[MatrixDataSource]
	public async Task CharPathsHandleVectorBoundaries([MatrixMethod<Base32SimdTest>(nameof(SupportedPaths))] string pathName, [MatrixMethod<Base32SimdTest>(nameof(VectorBoundaryLengths))] int sourceLength, [Matrix] bool hex)
	{
		Base32Encoding encoding = hex ? Base32Encoding.Rfc4648Hex : Base32Encoding.Rfc4648;
		Base32SimdPath path = Enum.Parse<Base32SimdPath>(pathName);

		byte[] source = new byte[sourceLength];

		for (int i = 0; i < source.Length; ++i)
		{
			source[i] = (byte)(i * 37 + sourceLength * 11);
		}

		char[] expected = EncodeReference(source, hex, false);
		char[] encoded = new char[expected.Length];
		byte[] decoded = new byte[source.Length];

		OperationStatus encodeStatus = encoding.EncodeToCharsPath(source, encoded, out int encodeConsumed, out int encodeWritten, true, path);
		OperationStatus decodeStatus = encoding.DecodeFromCharsPath(encoded, decoded, out int decodeConsumed, out int decodeWritten, true, path);

		await Assert.That(encodeStatus).IsEqualTo(OperationStatus.Done);
		await Assert.That(decodeStatus).IsEqualTo(OperationStatus.Done);
		await Assert.That(encodeConsumed).IsEqualTo(source.Length);
		await Assert.That(encodeWritten).IsEqualTo(expected.Length);
		await Assert.That(decodeConsumed).IsEqualTo(expected.Length);
		await Assert.That(decodeWritten).IsEqualTo(source.Length);
		await Assert.That(encoded).IsEquivalentTo(expected, CollectionOrdering.Matching);
		await Assert.That(decoded).IsEquivalentTo(source, CollectionOrdering.Matching);
	}

	[Test]
	[MatrixDataSource]
	public async Task CharSimdPathsReportLateInvalidDataLikeScalar([MatrixMethod<Base32SimdTest>(nameof(SupportedSimdPaths))] string pathName, [Matrix('!', '\u0080', '\u0100')] char invalidSymbol, [MatrixMethod<Base32SimdTest>(nameof(LateInvalidOffsets))] int invalidOffset)
	{
		const int sourceLength = 205;
		Base32SimdPath path = Enum.Parse<Base32SimdPath>(pathName);
		Skip.When(path is Base32SimdPath.Scalar, "No supported SIMD instruction set is available.");
		byte[] source = new byte[sourceLength];

		for (int i = 0; i < source.Length; ++i)
		{
			source[i] = (byte)(i * 37 + 11);
		}

		char[] encoded = EncodeReference(source, false, false);

		encoded[invalidOffset] = invalidSymbol;
		byte[] scalarDestination = Enumerable.Repeat(DestinationSentinel, source.Length).ToArray();
		byte[] simdDestination = Enumerable.Repeat(DestinationSentinel, source.Length).ToArray();

		OperationStatus scalarStatus = Base32Encoding.Rfc4648.DecodeFromCharsPath(encoded, scalarDestination, out int scalarConsumed, out int scalarWritten, true, Base32SimdPath.Scalar);
		OperationStatus simdStatus = Base32Encoding.Rfc4648.DecodeFromCharsPath(encoded, simdDestination, out int simdConsumed, out int simdWritten, true, path);

		int expectedConsumed = invalidOffset / 8 * 8;
		byte[] expected = source.AsSpan().Slice(0, invalidOffset / 8 * 5).ToArray();
		await Assert.That(scalarStatus).IsEqualTo(OperationStatus.InvalidData);
		await Assert.That(simdStatus).IsEqualTo(OperationStatus.InvalidData);
		await Assert.That(scalarConsumed).IsEqualTo(expectedConsumed);
		await Assert.That(simdConsumed).IsEqualTo(expectedConsumed);
		await AssertOutput(scalarDestination, expected, scalarWritten);
		await AssertOutput(simdDestination, expected, simdWritten);
	}
}
