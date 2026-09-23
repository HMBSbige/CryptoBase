using CryptoBase.Ciphers.Modes.Gcm;
using System.Buffers.Binary;
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
		byte[] expected = Convert.FromHexString(expectedHex);
		byte[] keyCopy = (byte[])key.Clone();
		byte[] sourceCopy = (byte[])source.Clone();
		byte[] destination = new byte[GHashAlgorithmCore.BlockSizeInBytes + 1];

		PrepareDestination(destination);
		int written = HashPaddedSegments(key, source, default, default, destination);

		await AssertOutput(destination, expected, written);
		await Assert.That(key).IsEquivalentTo(keyCopy, CollectionOrdering.Matching);
		await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);
		await Assert.That(ComputeReferenceHash(key, source, default, default)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[MethodDataSource(nameof(BoundaryLengths))]
	public async Task PaddedSegmentsMatchReferenceAndReset(int length)
	{
		byte[] key = CreateDeterministicSource(GHashAlgorithmCore.BlockSizeInBytes);
		byte[] first = CreateDeterministicSource(length);
		byte[] second = CreateDeterministicSource((length * 7 + 3) % 67);
		byte[] third = CreateDeterministicSource((length * 11 + 5) % 79);
		byte[] expected = ComputeReferenceHash(key, first, second, third);
		byte[] destination = new byte[GHashAlgorithmCore.BlockSizeInBytes + 1];
		byte[] resetDestination = new byte[destination.Length];
		GHashKey keyContext = GHashKey.Create(key);
		int written;
		int resetWritten;

		try
		{
			using GHashAlgorithmCore hash = GHashAlgorithmCore.Create(ref keyContext);
			hash.AppendPaddedSegment(first);
			PrepareDestination(destination);
			written = hash.HashPaddedSegmentsAndReset(second, third, default, destination);

			PrepareDestination(resetDestination);
			resetWritten = hash.HashPaddedSegmentsAndReset(default, default, default, resetDestination);
		}
		finally
		{
			keyContext.Dispose();
		}

		await AssertOutput(destination, expected, written);
		await AssertOutput(resetDestination, new byte[GHashAlgorithmCore.BlockSizeInBytes], resetWritten);
	}

	[Test]
	public async Task SegmentBoundariesArePreserved()
	{
		byte[] key = CreateDeterministicSource(GHashAlgorithmCore.BlockSizeInBytes);
		byte[] first = [0x01];
		byte[] second = [0x02];
		byte[] combined = Concat(first, second);
		byte[] segmentedHash = new byte[GHashAlgorithmCore.BlockSizeInBytes];
		byte[] combinedHash = new byte[GHashAlgorithmCore.BlockSizeInBytes];

		HashPaddedSegments(key, first, second, default, segmentedHash);
		HashPaddedSegments(key, combined, default, default, combinedHash);

		await Assert.That(segmentedHash).IsEquivalentTo(ComputeReferenceHash(key, first, second, default), CollectionOrdering.Matching);
		await Assert.That(combinedHash).IsEquivalentTo(ComputeReferenceHash(key, combined, default, default), CollectionOrdering.Matching);
		await Assert.That(segmentedHash).IsNotEquivalentTo(combinedHash, CollectionOrdering.Matching);
	}

	[Test]
	[MethodDataSource(nameof(BackendSelectionBoundaries))]
	public async Task BackendSelectionBoundariesMatchReference(int firstLength, int secondLength, int thirdLength)
	{
		byte[] key = CreateDeterministicSource(GHashAlgorithmCore.BlockSizeInBytes);
		byte[] first = CreateDeterministicSource(firstLength);
		byte[] second = CreateDeterministicSource(secondLength);
		byte[] third = CreateDeterministicSource(thirdLength);
		byte[] expected = ComputeReferenceHash(key, first, second, third);
		byte[] destination = new byte[GHashAlgorithmCore.BlockSizeInBytes + 1];

		PrepareDestination(destination);
		int written = HashPaddedSegments(key, first, second, third, destination);

		await AssertOutput(destination, expected, written);
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
		byte[] expected = ComputeReferenceHash(key, first, second, third);
		byte[] destination = new byte[GHashAlgorithmCore.BlockSizeInBytes + 1];

		PrepareDestination(destination);
		int written = HashPaddedSegments(key, first, second, third, destination);
		await AssertOutput(destination, expected, written);
	}

	[Test]
	public async Task ShortDestinationDoesNotModifyOutputOrState()
	{
		byte[] key = CreateDeterministicSource(GHashAlgorithmCore.BlockSizeInBytes);
		byte[] first = CreateDeterministicSource(23);
		byte[] second = CreateDeterministicSource(38);
		byte[] expected = ComputeReferenceHash(key, first, second, default);
		byte[] shortDestination = new byte[GHashAlgorithmCore.BlockSizeInBytes - 1];
		byte[] destination = new byte[GHashAlgorithmCore.BlockSizeInBytes + 1];
		GHashKey keyContext = GHashKey.Create(key);
		ArgumentOutOfRangeException? rejectedCall = null;
		int written;

		try
		{
			using GHashAlgorithmCore hash = GHashAlgorithmCore.Create(ref keyContext);
			hash.AppendPaddedSegment(first);
			PrepareDestination(shortDestination);

			try
			{
				hash.HashPaddedSegmentsAndReset(second, default, default, shortDestination);
			}
			catch (ArgumentOutOfRangeException exception)
			{
				rejectedCall = exception;
			}

			PrepareDestination(destination);
			written = hash.HashPaddedSegmentsAndReset(second, default, default, destination);
		}
		finally
		{
			keyContext.Dispose();
		}

		await Assert.That(rejectedCall?.GetType()).IsEqualTo(typeof(ArgumentOutOfRangeException));
		await Assert.That(rejectedCall?.ParamName).IsEqualTo("destination");
		await Assert.That(shortDestination).All(static value => value is DestinationSentinel);
		await AssertOutput(destination, expected, written);
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
		byte[] firstDestination = new byte[GHashAlgorithmCore.BlockSizeInBytes];
		byte[] secondDestination = new byte[GHashAlgorithmCore.BlockSizeInBytes];
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
				firstHash.HashPaddedSegmentsAndReset(prefix, default, default, firstDestination);
			}

			secondHash.HashPaddedSegmentsAndReset(second, default, default, secondDestination);
		}
		finally
		{
			keyContext.Dispose();
		}

		await Assert.That(firstDestination).IsEquivalentTo(ComputeReferenceHash(key, first, prefix, default), CollectionOrdering.Matching);
		await Assert.That(secondDestination).IsEquivalentTo(ComputeReferenceHash(key, prefix, second, default), CollectionOrdering.Matching);
	}

	private static int HashPaddedSegments(ReadOnlySpan<byte> key, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> third, Span<byte> destination)
	{
		GHashKey keyContext = GHashKey.Create(key);

		try
		{
			using GHashAlgorithmCore hash = GHashAlgorithmCore.Create(ref keyContext);
			return hash.HashPaddedSegmentsAndReset(first, second, third, destination);
		}
		finally
		{
			keyContext.Dispose();
		}
	}

	private static byte[] ComputeReferenceHash(ReadOnlySpan<byte> key, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> third)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, GHashAlgorithmCore.BlockSizeInBytes, nameof(key));

		UInt128 h = BinaryPrimitives.ReadUInt128BigEndian(key);
		UInt128 accumulator = 0;
		AppendPaddedSegment(ref accumulator, h, first);
		AppendPaddedSegment(ref accumulator, h, second);
		AppendPaddedSegment(ref accumulator, h, third);

		byte[] destination = new byte[GHashAlgorithmCore.BlockSizeInBytes];
		BinaryPrimitives.WriteUInt128BigEndian(destination, accumulator);
		return destination;
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
