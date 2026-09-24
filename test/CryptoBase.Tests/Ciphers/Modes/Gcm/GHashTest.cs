using CryptoBase.Ciphers.Modes.Gcm;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using static CryptoBase.Tests.TestUtils;
using GHashAlgorithmCore = CryptoBase.Ciphers.Modes.Gcm.GHash;

namespace CryptoBase.Tests.Ciphers.Modes.Gcm;

public class GHashTest
{
	private static readonly UInt128 ReductionPolynomial = (UInt128)0xe100000000000000UL << 64;

	public static IEnumerable<int> BoundaryLengths =>
	[
		0, 1, 2, 15, 16, 17, 31, 32, 33,
		63, 64, 65, 127, 128, 129, 239, 240, 241, 255, 256, 257,
		495, 496, 497, 511, 512, 513, 1023, 1024, 1025, 4095, 4096,
		4097, 8175, 8176, 8177, 8191, 8192, 8193
	];

	public static IEnumerable<(int, int, int)> BackendSelectionBoundaries =>
	[
		(96, 0, 0), (97, 0, 0), (112, 0, 0), (113, 0, 0), (129, 0, 0),
		(240, 0, 0), (241, 0, 0), (257, 0, 0),
		(496, 0, 0), (497, 0, 0), (513, 0, 0),
		(2032, 0, 0), (2033, 0, 0), (2034, 0, 0),
		(1024, 1008, 0), (1024, 1024, 0), (1024, 1025, 0)
	];

	/// <summary>
	/// https://csrc.nist.gov/pubs/sp/800/38/d/final
	/// https://www.intel.cn/content/dam/www/public/us/en/documents/white-papers/carry-less-multiplication-instruction-in-gcm-mode-paper.pdf
	/// </summary>
	public static IEnumerable<(string, string, string)> Data =>
	[
		(@"dfa6bf4ded81db03ffcaff95f830f061", @"952b2a56a5604ac0b32b6656a05b40b6", @"da53eb0ad2c55bb64fc4802cc3feda60"),
		(@"66e94bd4ef8a2c3b884cfa59ca342b2e", @"", @"00000000000000000000000000000000"),
		(@"66e94bd4ef8a2c3b884cfa59ca342b2e", @"0388dace60b6a392f328c2b971b2fe78", @"5e2ec746917062882c85b0685353deb7"),
		(@"66e94bd4ef8a2c3b884cfa59ca342b2e", @"0388dace60b6a392f328c2b971b2fe7800000000000000000000000000000080", @"f38cbb1ad69223dcc3457ae5b6b0f885"),
		(@"66e94bd4ef8a2c3b884cfa59ca342b2e", @"0388dace60b6a392f328c2b971b2fe7ad2c55bb64f", @"c1d3b69b62c9a392687aaf55d95a1df6")
	];

	[Test]
	[MethodDataSource(nameof(Data))]
	public async Task KnownVectors(string keyHex, string sourceHex, string expectedHex)
	{
		byte[] key = Convert.FromHexString(keyHex);
		byte[] source = Convert.FromHexString(sourceHex);
		Vector128<byte> expected = MemoryMarshal.Read<Vector128<byte>>(Convert.FromHexString(expectedHex));
		byte[] keyCopy = (byte[])key.Clone();
		byte[] sourceCopy = (byte[])source.Clone();
		Vector128<byte> actual = HashPaddedSegments(key, source, default, default);

		await Assert.That(actual).IsEqualTo(expected);
		await Assert.That(key).IsEquivalentTo(keyCopy, CollectionOrdering.Matching);
		await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);
		await Assert.That(ComputeReferenceHash(key, source, default, default)).IsEqualTo(expected);
	}

	[Test]
	[MethodDataSource(nameof(BoundaryLengths))]
	public async Task PaddedSegmentsMatchReference(int length)
	{
		byte[] key = CreateDeterministicSource(GHashAlgorithmCore.BlockSizeInBytes);
		byte[] first = CreateDeterministicSource(length);
		byte[] second = CreateDeterministicSource((length * 7 + 3) % 67);
		byte[] third = CreateDeterministicSource((length * 11 + 5) % 79);
		Vector128<byte> expected = ComputeReferenceHash(key, first, second, third);
		GHashKey keyContext = GHashKey.Create(key);
		Vector128<byte> actual;

		try
		{
			using GHashAlgorithmCore hash = GHashAlgorithmCore.Create(ref keyContext);
			hash.AppendPaddedSegment(first);
			actual = hash.Finish(second, third, default);
		}
		finally
		{
			keyContext.Dispose();
		}

		await Assert.That(actual).IsEqualTo(expected);
	}

	[Test]
	public async Task SegmentBoundariesArePreserved()
	{
		byte[] key = CreateDeterministicSource(GHashAlgorithmCore.BlockSizeInBytes);
		byte[] first = [0x01];
		byte[] second = [0x02];
		byte[] combined = Concat(first, second);
		Vector128<byte> segmentedHash = HashPaddedSegments(key, first, second, default);
		Vector128<byte> combinedHash = HashPaddedSegments(key, combined, default, default);

		await Assert.That(segmentedHash).IsEqualTo(ComputeReferenceHash(key, first, second, default));
		await Assert.That(combinedHash).IsEqualTo(ComputeReferenceHash(key, combined, default, default));
		await Assert.That(segmentedHash).IsNotEqualTo(combinedHash);
	}

	[Test]
	[MethodDataSource(nameof(BackendSelectionBoundaries))]
	public async Task BackendSelectionBoundariesMatchReference(int firstLength, int secondLength, int thirdLength)
	{
		byte[] key = CreateDeterministicSource(GHashAlgorithmCore.BlockSizeInBytes);
		byte[] first = CreateDeterministicSource(firstLength);
		byte[] second = CreateDeterministicSource(secondLength);
		byte[] third = CreateDeterministicSource(thirdLength);
		Vector128<byte> expected = ComputeReferenceHash(key, first, second, third);
		Vector128<byte> actual = HashPaddedSegments(key, first, second, third);

		await Assert.That(actual).IsEqualTo(expected);
	}

	[Test]
	[MatrixDataSource]
	public async Task LargePaddedSegmentsMatchReference([Matrix(8191, 8192, 8193, 9200, 9216)] int length, [Matrix(0, 1, 15, 31, 63)] int offset)
	{
		byte[] key = CreateDeterministicSource(GHashAlgorithmCore.BlockSizeInBytes);
		byte[] first = CreateDeterministicSource(13);
		byte[] third = CreateDeterministicSource(19);
		byte[] source = CreateDeterministicSource(offset + length);
		ReadOnlySpan<byte> second = source.AsSpan().Slice(offset, length);
		Vector128<byte> expected = ComputeReferenceHash(key, first, second, third);
		Vector128<byte> actual = HashPaddedSegments(key, first, second, third);

		await Assert.That(actual).IsEqualTo(expected);
	}

	[Test]
	[Arguments(GHashAlgorithmCore.BlockSizeInBytes - 1)]
	[Arguments(GHashAlgorithmCore.BlockSizeInBytes + 1)]
	public async Task KeyMustBeExactlyOneBlock(int keyLength)
	{
		byte[] key = CreateDeterministicSource(keyLength);

		await Assert.That(() => GHashKey.Create(key)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("key");
	}

	[Test]
	public async Task SharedKeyKeepsMessageStatesIndependent()
	{
		byte[] key = CreateDeterministicSource(GHashAlgorithmCore.BlockSizeInBytes);
		byte[] first = CreateDeterministicSource(513);
		byte[] second = CreateDeterministicSource(4097);
		byte[] prefix = CreateDeterministicSource(17);
		Vector128<byte> firstResult;
		Vector128<byte> secondResult;
		GHashKey keyContext = GHashKey.Create(key);

		try
		{
			using GHashAlgorithmCore secondHash = GHashAlgorithmCore.Create(ref keyContext);

			using (GHashAlgorithmCore discardedHash = GHashAlgorithmCore.Create(ref keyContext))
			{
				discardedHash.AppendPaddedSegment(prefix);
				secondHash.AppendPaddedSegment(prefix);
			}

			using (GHashAlgorithmCore firstHash = GHashAlgorithmCore.Create(ref keyContext))
			{
				firstHash.AppendPaddedSegment(first);
				firstResult = firstHash.Finish(prefix, default, default);
			}

			secondResult = secondHash.Finish(second, default, default);
		}
		finally
		{
			keyContext.Dispose();
		}

		await Assert.That(firstResult).IsEqualTo(ComputeReferenceHash(key, first, prefix, default));
		await Assert.That(secondResult).IsEqualTo(ComputeReferenceHash(key, prefix, second, default));
	}

	private static Vector128<byte> HashPaddedSegments(ReadOnlySpan<byte> key, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> third)
	{
		GHashKey keyContext = GHashKey.Create(key);

		try
		{
			using GHashAlgorithmCore hash = GHashAlgorithmCore.Create(ref keyContext);
			return hash.Finish(first, second, third);
		}
		finally
		{
			keyContext.Dispose();
		}
	}

	private static Vector128<byte> ComputeReferenceHash(ReadOnlySpan<byte> key, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> third)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, GHashAlgorithmCore.BlockSizeInBytes, nameof(key));

		UInt128 h = BinaryPrimitives.ReadUInt128BigEndian(key);
		UInt128 accumulator = 0;
		AppendPaddedSegment(ref accumulator, h, first);
		AppendPaddedSegment(ref accumulator, h, second);
		AppendPaddedSegment(ref accumulator, h, third);

		Span<byte> destination = stackalloc byte[GHashAlgorithmCore.BlockSizeInBytes];
		BinaryPrimitives.WriteUInt128BigEndian(destination, accumulator);
		return MemoryMarshal.Read<Vector128<byte>>(destination);
	}

	private static void AppendPaddedSegment(ref UInt128 accumulator, UInt128 key, ReadOnlySpan<byte> source)
	{
		while (source.Length >= GHashAlgorithmCore.BlockSizeInBytes)
		{
			accumulator = Multiply(accumulator ^ BinaryPrimitives.ReadUInt128BigEndian(source), key);
			source = source.Slice(GHashAlgorithmCore.BlockSizeInBytes);
		}

		if (source.IsEmpty)
		{
			return;
		}

		Span<byte> finalBlock = stackalloc byte[GHashAlgorithmCore.BlockSizeInBytes];
		finalBlock.Clear();
		source.CopyTo(finalBlock);
		accumulator = Multiply(accumulator ^ BinaryPrimitives.ReadUInt128BigEndian(finalBlock), key);
	}

	private static UInt128 Multiply(UInt128 x, UInt128 y)
	{
		UInt128 product = 0;
		UInt128 multiplier = y;
		UInt128 mask = (UInt128)1 << 127;

		for (int i = 0; i < 128; ++i)
		{
			if ((x & mask) != 0)
			{
				product ^= multiplier;
			}

			bool reductionRequired = (multiplier & 1) != 0;
			multiplier >>= 1;

			if (reductionRequired)
			{
				multiplier ^= ReductionPolynomial;
			}

			mask >>= 1;
		}

		return product;
	}
}
