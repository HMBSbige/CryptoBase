using CryptoBase.DataFormatExtensions;
using System.Buffers;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using static CryptoBase.Tests.DataFormatExtensions.Base32TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.DataFormatExtensions;

public class Base32SimdPathTest
{
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

		await Assert.That(encoding.DecodeUtf8BlocksPath(valid, actual, path)).IsEqualTo(GetVectorizedLength(path, symbolCount));

		for (int value = 0; value <= byte.MaxValue; ++value)
		{
			for (int position = 0; position < symbolCount; ++position)
			{
				valid.CopyTo(input, 0);
				input[position] = (byte)value;
				PrepareDestination(expected);
				PrepareDestination(actual);
				OperationStatus expectedStatus = encoding.DecodeFromUtf8Path(input, expected, out int expectedConsumed, out int expectedWritten, true, Base32SimdPath.Scalar);
				OperationStatus actualStatus = encoding.DecodeFromUtf8Path(input, actual, out int actualConsumed, out int actualWritten, true, path);

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

		await Assert.That(encoding.DecodeCharsBlocksPath(valid, actual, path)).IsEqualTo(GetVectorizedLength(path, symbolCount));

		foreach (char symbol in Enumerable.Range(0, 0x100).Select(static value => (char)value).Concat(WideChars))
		{
			for (int position = 0; position < symbolCount; ++position)
			{
				valid.CopyTo(input, 0);
				input[position] = symbol;
				PrepareDestination(expected);
				PrepareDestination(actual);
				OperationStatus expectedStatus = encoding.DecodeFromCharsPath(input, expected, out int expectedConsumed, out int expectedWritten, true, Base32SimdPath.Scalar);
				OperationStatus actualStatus = encoding.DecodeFromCharsPath(input, actual, out int actualConsumed, out int actualWritten, true, path);

				if (actualStatus != expectedStatus || actualConsumed != expectedConsumed || actualWritten != expectedWritten || !actual.AsSpan().SequenceEqual(expected))
				{
					failures.Add($"U+{(int)symbol:X4} at {position}: {actualStatus}/{actualConsumed}/{actualWritten}, scalar {expectedStatus}/{expectedConsumed}/{expectedWritten}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
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
			Base32SimdPath.Avx512VbmiVl256 or Base32SimdPath.Avx512VbmiVl128 => Avx512Vbmi.VL.IsSupported && Avx512BW.VL.IsSupported,
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
