using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using System.Buffers.Binary;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes;

public static class CrcTestUtils
{
	public static IEnumerable<int> SplitBoundaryLengths => [0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 511, 512, 513, 527, 528, 1023, 1024, 1025];

	public static IEnumerable<int> SplitSizes => [0, 1, 7, 8, 15, 16, 17, 63, 64, 65, 127, 128, 129, 511, 512];

	public static IEnumerable<int> BlockBoundaryLengths =>
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

	public static async Task VerifySplitBoundary<T>(int length, int splitSize, uint polynomial) where T : unmanaged, IHashCore<T>
	{
		byte[] source = CreateDeterministicSource(length);
		byte[] expected = ComputeReference(source, polynomial);
		byte[] destination = new byte[T.HashLengthInBytes + 1];

		int firstLength = Math.Min(splitSize, source.Length);
		using HashAlgorithm<T> hashAlgorithm = HashAlgorithm<T>.Create();
		hashAlgorithm.Append(source.AsSpan().Slice(0, firstLength));
		hashAlgorithm.Append(source.AsSpan().Slice(firstLength));
		PrepareDestination(destination);

		int written = hashAlgorithm.GetHashAndReset(destination);

		await AssertOutput(destination, expected, written);
	}

	public static Task VerifyBlockBoundary<T>(int length, int offset, uint polynomial) where T : unmanaged, IHashCore<T>
	{
		byte[] source = CreateDeterministicSource(offset + length);
		ReadOnlyMemory<byte> input = source.AsMemory().Slice(offset, length);
		return HashAlgorithmTestUtils.VerifyBoundary<T>(input, ComputeReference(input.Span, polynomial));
	}

	private static byte[] ComputeReference(ReadOnlySpan<byte> source, uint polynomial)
	{
		uint crc = uint.MaxValue;

		foreach (byte value in source)
		{
			crc ^= value;

			for (int bit = 0; bit < 8; ++bit)
			{
				crc = (crc & 1) is 0 ? crc >> 1 : polynomial ^ crc >> 1;
			}
		}

		byte[] expected = new byte[sizeof(uint)];
		BinaryPrimitives.WriteUInt32BigEndian(expected, ~crc);
		return expected;
	}
}
