using CryptoBase.Encodings;
using System.Buffers;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using static CryptoBase.Tests.Encodings.Base32TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Encodings;

public class Base32SimdPathTest
{
	private const char CharSentinel = (char)0xA5A5;
	private static readonly char[] WideChars = [(char)0x0100, (char)0x0141, (char)0x0172, (char)0x7F41, (char)0x8041, (char)0xFF41, (char)0xFFFF];

	public static IEnumerable<string> SimdPaths()
	{
		return Enum.GetNames<Base32SimdPath>().Where(static name => name is not (nameof(Base32SimdPath.Auto) or nameof(Base32SimdPath.Scalar)));
	}

	[Test]
	[MatrixDataSource]
	public async Task Utf8DecodeMatchesScalarForEveryByte([MatrixMethod<Base32SimdPathTest>(nameof(SimdPaths))] string pathName, [Matrix(112, 192)] int symbolCount, [Matrix] bool hex)
	{
		Base32SimdPath path = GetSupportedPath(pathName);
		Base32Encoding encoding = hex ? Base32Encoding.Rfc4648Hex : Base32Encoding.Rfc4648;
		byte[] valid = ToByteSymbols(EncodeReference(CreateDeterministicSource(symbolCount / 8 * 5), hex, false));
		byte[] input = new byte[symbolCount];
		byte[] expected = new byte[symbolCount / 8 * 5];
		byte[] actual = new byte[expected.Length];
		List<string> failures = [];

		await Assert.That(encoding.DecodeBlocksPath(valid, actual, path)).IsEqualTo(GetVectorizedLength(path, symbolCount));

		for (int value = 0; value <= byte.MaxValue; ++value)
		{
			for (int position = 0; position < symbolCount; ++position)
			{
				valid.CopyTo(input, 0);
				input[position] = (byte)value;
				PrepareDestination(expected);
				PrepareDestination(actual);
				OperationStatus expectedStatus = encoding.DecodeCore(input, expected, out int expectedConsumed, out int expectedWritten, true, Base32SimdPath.Scalar);
				OperationStatus actualStatus = encoding.DecodeCore(input, actual, out int actualConsumed, out int actualWritten, true, path);

				if (actualStatus != expectedStatus || actualConsumed != expectedConsumed || actualWritten != expectedWritten || !actual.AsSpan().SequenceEqual(expected))
				{
					failures.Add($"0x{value:X2} at {position}: {actualStatus}/{actualConsumed}/{actualWritten}, scalar {expectedStatus}/{expectedConsumed}/{expectedWritten}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MatrixDataSource]
	public async Task CharDecodeMatchesScalarForEveryChar([MatrixMethod<Base32SimdPathTest>(nameof(SimdPaths))] string pathName, [Matrix(112, 192)] int symbolCount, [Matrix] bool hex)
	{
		Base32SimdPath path = GetSupportedPath(pathName);
		Base32Encoding encoding = hex ? Base32Encoding.Rfc4648Hex : Base32Encoding.Rfc4648;
		char[] valid = EncodeReference(CreateDeterministicSource(symbolCount / 8 * 5), hex, false);
		char[] input = new char[symbolCount];
		byte[] expected = new byte[symbolCount / 8 * 5];
		byte[] actual = new byte[expected.Length];
		List<string> failures = [];

		await Assert.That(encoding.DecodeBlocksPath(valid, actual, path)).IsEqualTo(GetVectorizedLength(path, symbolCount));

		foreach (char symbol in Enumerable.Range(0, 0x100).Select(static value => (char)value).Concat(WideChars))
		{
			for (int position = 0; position < symbolCount; ++position)
			{
				valid.CopyTo(input, 0);
				input[position] = symbol;
				PrepareDestination(expected);
				PrepareDestination(actual);
				OperationStatus expectedStatus = encoding.DecodeCore(input, expected, out int expectedConsumed, out int expectedWritten, true, Base32SimdPath.Scalar);
				OperationStatus actualStatus = encoding.DecodeCore(input, actual, out int actualConsumed, out int actualWritten, true, path);

				if (actualStatus != expectedStatus || actualConsumed != expectedConsumed || actualWritten != expectedWritten || !actual.AsSpan().SequenceEqual(expected))
				{
					failures.Add($"U+{(int)symbol:X4} at {position}: {actualStatus}/{actualConsumed}/{actualWritten}, scalar {expectedStatus}/{expectedConsumed}/{expectedWritten}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MatrixDataSource]
	public async Task EncodeMatchesScalarForEveryDestinationLength([MatrixMethod<Base32SimdPathTest>(nameof(SimdPaths))] string pathName, [Matrix] bool hex)
	{
		Base32SimdPath path = GetSupportedPath(pathName);
		Base32Encoding encoding = hex ? Base32Encoding.Rfc4648Hex : Base32Encoding.Rfc4648;
		byte[] source = CreateDeterministicSource(240);
		byte[] encoded = new byte[encoding.GetEncodedLength(source.Length)];

		await Assert.That(encoding.EncodeBlocksPath(source, encoded, path)).IsGreaterThan(0);
		await Assert.That(encoding.EncodeBlocksPath(source, new char[encoded.Length], path)).IsGreaterThan(0);
		await Assert.That(GetEncodeMismatches(encoding, source, path)).IsEmpty();
	}

	// Auto picks the short, overlapping and tail paths from the source and destination lengths, so every length pair is compared with Scalar.
	[Test]
	[MatrixDataSource]
	public async Task AutoEncodeMatchesScalarForEveryDestinationLength([Matrix("rfc", "hex", "custom")] string alphabet, [Matrix] bool omitPadding)
	{
		Base32Encoding encoding = CreateEncoding(alphabet);

		if (omitPadding)
		{
			encoding = encoding.OmitPadding;
		}

		await Assert.That(GetEncodeMismatches(encoding, CreateDeterministicSource(240), Base32SimdPath.Auto)).IsEmpty();
	}

	[Test]
	[MatrixDataSource]
	public async Task EncodeDoesNotReadPastSource([MatrixMethod<Base32SimdPathTest>(nameof(SimdPaths))] string pathName, [Matrix] bool hex)
	{
		GuardPageBuffer.SkipUnlessSupported();
		Base32SimdPath path = GetSupportedPath(pathName);

		await Assert.That(GetGuardedEncodeMismatches(hex ? Base32Encoding.Rfc4648Hex : Base32Encoding.Rfc4648, path)).IsEmpty();
	}

	[Test]
	[MatrixDataSource]
	public async Task AutoEncodeDoesNotReadPastSource([Matrix("rfc", "hex", "custom")] string alphabet)
	{
		GuardPageBuffer.SkipUnlessSupported();

		await Assert.That(GetGuardedEncodeMismatches(CreateEncoding(alphabet), Base32SimdPath.Auto)).IsEmpty();
	}

	private static Base32Encoding CreateEncoding(string alphabet)
	{
		return alphabet switch
		{
			"hex" => Base32Encoding.Rfc4648Hex,
			"custom" => Base32Encoding.Create(LowercaseAlphabet),
			_ => Base32Encoding.Rfc4648,
		};
	}

	private static List<string> GetGuardedEncodeMismatches(Base32Encoding encoding, Base32SimdPath path)
	{
		byte[] source = CreateDeterministicSource(240);
		using GuardPageBuffer guarded = new(source.Length);
		source.CopyTo(guarded.Span);
		List<string> failures = [];

		for (int length = 0; length <= source.Length; ++length)
		{
			ReadOnlySpan<byte> input = source.AsSpan(source.Length - length);
			ReadOnlySpan<byte> guardedInput = guarded.Span.Slice(source.Length - length);
			byte[] utf8Expected = new byte[encoding.GetEncodedLength(length)];
			byte[] utf8Actual = new byte[utf8Expected.Length];
			char[] charsExpected = new char[utf8Expected.Length];
			char[] charsActual = new char[utf8Expected.Length];
			encoding.EncodeCore(input, utf8Expected, out _, out _, true, Base32SimdPath.Scalar);
			encoding.EncodeCore(guardedInput, utf8Actual, out _, out _, true, path);
			encoding.EncodeCore(input, charsExpected, out _, out _, true, Base32SimdPath.Scalar);
			encoding.EncodeCore(guardedInput, charsActual, out _, out _, true, path);

			if (!utf8Actual.AsSpan().SequenceEqual(utf8Expected))
			{
				failures.Add($"UTF-8 {length}");
			}

			if (!charsActual.AsSpan().SequenceEqual(charsExpected))
			{
				failures.Add($"Chars {length}");
			}
		}

		return failures;
	}

	private static List<string> GetEncodeMismatches(Base32Encoding encoding, byte[] source, Base32SimdPath path)
	{
		byte[] utf8Expected = new byte[encoding.GetEncodedLength(source.Length)];
		byte[] utf8Actual = new byte[utf8Expected.Length];
		char[] charsExpected = new char[utf8Expected.Length];
		char[] charsActual = new char[utf8Expected.Length];
		List<string> failures = [];

		for (int length = 0; length <= source.Length; ++length)
		{
			ReadOnlySpan<byte> input = source.AsSpan(0, length);

			for (int destinationLength = 0; destinationLength <= encoding.GetEncodedLength(length); ++destinationLength)
			{
				PrepareDestination(utf8Expected);
				PrepareDestination(utf8Actual);
				charsExpected.AsSpan().Fill(CharSentinel);
				charsActual.AsSpan().Fill(CharSentinel);
				OperationStatus utf8ExpectedStatus = encoding.EncodeCore(input, utf8Expected.AsSpan(0, destinationLength), out int utf8ExpectedConsumed, out int utf8ExpectedWritten, true, Base32SimdPath.Scalar);
				OperationStatus utf8ActualStatus = encoding.EncodeCore(input, utf8Actual.AsSpan(0, destinationLength), out int utf8ActualConsumed, out int utf8ActualWritten, true, path);
				OperationStatus charsExpectedStatus = encoding.EncodeCore(input, charsExpected.AsSpan(0, destinationLength), out int charsExpectedConsumed, out int charsExpectedWritten, true, Base32SimdPath.Scalar);
				OperationStatus charsActualStatus = encoding.EncodeCore(input, charsActual.AsSpan(0, destinationLength), out int charsActualConsumed, out int charsActualWritten, true, path);

				if (utf8ActualStatus != utf8ExpectedStatus || utf8ActualConsumed != utf8ExpectedConsumed || utf8ActualWritten != utf8ExpectedWritten || !utf8Actual.AsSpan().SequenceEqual(utf8Expected))
				{
					failures.Add($"UTF-8 {length}/{destinationLength}: {utf8ActualStatus}/{utf8ActualConsumed}/{utf8ActualWritten}, scalar {utf8ExpectedStatus}/{utf8ExpectedConsumed}/{utf8ExpectedWritten}");
				}

				if (charsActualStatus != charsExpectedStatus || charsActualConsumed != charsExpectedConsumed || charsActualWritten != charsExpectedWritten || !charsActual.AsSpan().SequenceEqual(charsExpected))
				{
					failures.Add($"Chars {length}/{destinationLength}: {charsActualStatus}/{charsActualConsumed}/{charsActualWritten}, scalar {charsExpectedStatus}/{charsExpectedConsumed}/{charsExpectedWritten}");
				}
			}
		}

		return failures;
	}

	private static Base32SimdPath GetSupportedPath(string pathName)
	{
		Base32SimdPath path = Enum.Parse<Base32SimdPath>(pathName);

		bool isSupported = path switch
		{
			Base32SimdPath.Ssse3 => Ssse3.IsSupported,
			Base32SimdPath.Avx2 => Avx2.IsSupported,
			Base32SimdPath.Avx512Bw => Avx512BW.IsSupported,
			Base32SimdPath.Avx512Vbmi => Avx512Vbmi.IsSupported && Avx512BW.IsSupported,
			Base32SimdPath.Avx512VbmiVl256 => Avx512Vbmi.VL.IsSupported && Avx512BW.VL.IsSupported,
			Base32SimdPath.AdvSimd => AdvSimd.IsSupported,
			_ => throw new ArgumentOutOfRangeException(nameof(pathName), pathName, "Add the new SIMD path to this test."),
		};

		if (!isSupported)
		{
			Skip.Test($"{path} is not supported here.");
		}

		return path;
	}

	private static int GetVectorizedLength(Base32SimdPath path, int symbolCount)
	{
		int blockSymbols = path switch
		{
			Base32SimdPath.Avx512Bw or Base32SimdPath.Avx512Vbmi => 64,
			Base32SimdPath.Avx2 or Base32SimdPath.Avx512VbmiVl256 => 32,
			_ => 16,
		};

		return symbolCount / blockSymbols * blockSymbols;
	}
}
