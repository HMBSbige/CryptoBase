using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Crc32;
using System.Buffers.Binary;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Crc32;

[GenerateGenericTest(typeof(Crc32Core))]
[GenerateGenericTest(typeof(Crc32CCore))]
public class Crc32Test<T> where T : unmanaged, IHashCore<T>
{
	// The reflected polynomial and the CRC of "123456789".
	private static readonly (uint Polynomial, string Check) Case = typeof(T).Name switch
	{
		nameof(Crc32Core) => (0xedb88320, "cbf43926"),
		nameof(Crc32CCore) => (0x82f63b78, "e3069283"),
		_ => throw new NotSupportedException(typeof(T).Name)
	};

	private static IEnumerable<int> SplitBoundaryLengths => [0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 511, 512, 513, 527, 528, 1023, 1024, 1025];

	private static IEnumerable<int> SplitSizes => [0, 1, 7, 8, 15, 16, 17, 63, 64, 65, 127, 128, 129, 511, 512];

	private static IEnumerable<int> BlockBoundaryLengths =>
	[
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
		31, 32, 33,
		39, 40, 41,
		63, 64, 65,
		127, 128, 129,
		255, 256, 257,
		511, 512, 513, 527, 528,
		1023, 1024, 1025,
		1279, 1280, 1281,
		4095, 4096, 4097,
		6143, 6144, 6145,
		8191, 8192, 8193,
		32767, 32768, 32769
	];

	public static IEnumerable<(string, string)> Vectors => [("", "00000000"), ("123456789", Case.Check)];

	public static IEnumerable<(int Length, int Offset)> BlockBoundaryCases()
	{
		return BlockBoundaryLengths.SelectMany(static _ => (int[])[0, 1, 3, 15], static (length, offset) => (length, offset));
	}

	public static IEnumerable<(int Length, int SplitSize)> SplitBoundaryCases()
	{
		return SplitBoundaryLengths.SelectMany(length => SplitSizes.Select(size => Math.Min(size, length)).Distinct(), (length, splitSize) => (length, splitSize));
	}

	[Test]
	[MethodDataSource(nameof(Vectors))]
	public Task KnownVectors(string value, string expected)
	{
		return VerifyHashVector<T>(value, expected, sizeof(uint));
	}

	[Test]
	[MethodDataSource(nameof(BlockBoundaryCases))]
	public Task BlockBoundaries(int length, int offset)
	{
		byte[] source = CreateDeterministicSource(offset + length);
		ReadOnlyMemory<byte> input = source.AsMemory().Slice(offset, length);
		return VerifyBoundary<T>(input, ComputeReference(input.Span));
	}

	[Test]
	[MethodDataSource(nameof(SplitBoundaryCases))]
	public async Task IncrementalBlockBatches(int length, int splitSize)
	{
		byte[] source = CreateDeterministicSource(length);
		byte[] expected = ComputeReference(source);
		byte[] destination = new byte[T.HashLength + 1];

		using HashAlgorithm<T> hashAlgorithm = HashAlgorithm<T>.Create();
		hashAlgorithm.Append(source.AsSpan().Slice(0, splitSize));
		hashAlgorithm.Append(source.AsSpan().Slice(splitSize));
		PrepareDestination(destination);

		int written = hashAlgorithm.GetHashAndReset(destination);

		await AssertOutput(destination, expected, written);
	}

	[Test]
	[CombinedDataSources]
	public Task InputIsUnchanged([MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(InputIntegrityLengths))] int length, [Arguments(1, 7)] int offset)
	{
		return VerifyInputIsUnchanged<T>(length, offset);
	}

	private static byte[] ComputeReference(ReadOnlySpan<byte> source)
	{
		uint crc = uint.MaxValue;

		foreach (byte value in source)
		{
			crc ^= value;

			for (int bit = 0; bit < 8; ++bit)
			{
				crc = (crc & 1) is 0 ? crc >> 1 : Case.Polynomial ^ crc >> 1;
			}
		}

		byte[] expected = new byte[sizeof(uint)];
		BinaryPrimitives.WriteUInt32BigEndian(expected, ~crc);
		return expected;
	}
}
