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

	/// <summary>
	/// NIST GCM-AES128 examples 2, 3 and 5, including the intermediate GHASH value S.
	/// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf
	/// </summary>
	public static IEnumerable<(string, string, string)> NistGcmData =>
	[
		("", "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985", "7f1b32b81b820d02614f8895ac1d4eac"),
		("3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4", "", "6dd6cf3a1fa0371dd4c5c1ac1c3675f1"),
		("3ad77bb40d7a3660a89ecaf32466ef97f5d3d585", "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", "c23b3d63d2ed95056ca342769cd13c03")
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
		await Assert.That(HashSoftwarePaddedSegments(key, source, default, default)).IsEqualTo(expected);

		if (GHashNeon.IsSupported)
		{
			await Assert.That(HashNeonPaddedSegments(key, source, default, default)).IsEqualTo(expected);
		}

		await Assert.That(key).IsEquivalentTo(keyCopy, CollectionOrdering.Matching);
		await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);
		await Assert.That(ComputeReferenceHash(key, source, default, default)).IsEqualTo(expected);
	}

	[Test]
	[MethodDataSource(nameof(NistGcmData))]
	public async Task NistGcmKnownAnswers(string associatedDataHex, string ciphertextHex, string expectedHex)
	{
		byte[] key = Convert.FromHexString("b83b533708bf535d0aa6e52980d53b78");
		byte[] associatedData = Convert.FromHexString(associatedDataHex);
		byte[] ciphertext = Convert.FromHexString(ciphertextHex);
		byte[] lengths = new byte[GHashAlgorithmCore.BlockSizeInBytes];
		BinaryPrimitives.WriteUInt64BigEndian(lengths, (ulong)associatedData.Length * 8);
		BinaryPrimitives.WriteUInt64BigEndian(lengths.AsSpan().Slice(8), (ulong)ciphertext.Length * 8);
		Vector128<byte> expected = MemoryMarshal.Read<Vector128<byte>>(Convert.FromHexString(expectedHex));

		await Assert.That(HashSoftwarePaddedSegments(key, associatedData, ciphertext, lengths)).IsEqualTo(expected);
		await Assert.That(HashPaddedSegments(key, associatedData, ciphertext, lengths)).IsEqualTo(expected);
		await Assert.That(ComputeReferenceHash(key, associatedData, ciphertext, lengths)).IsEqualTo(expected);

		if (GHashNeon.IsSupported)
		{
			await Assert.That(HashNeonPaddedSegments(key, associatedData, ciphertext, lengths)).IsEqualTo(expected);
		}
	}

	[Test]
	public async Task SoftwareMultipliersMatchReferenceForBoundaryValues()
	{
		UInt128[] values = [0, 1, uint.MaxValue, ulong.MaxValue, (UInt128)ulong.MaxValue << 64, UInt128.MaxValue];

		foreach (UInt128 input in values)
		{
			foreach (UInt128 key in values)
			{
				await AssertSoftwareMultipliersMatchReference(input, key);
			}
		}

		for (int bit = 0; bit < 128; ++bit)
		{
			UInt128 singleBit = (UInt128)1 << bit;
			await AssertSoftwareMultipliersMatchReference(singleBit, UInt128.MaxValue);
			await AssertSoftwareMultipliersMatchReference(UInt128.MaxValue, singleBit);
		}
	}

	[Test]
	public async Task SoftwareMultipliersMatchReferenceForRandomInputs()
	{
		Random random = new(0x63746d75);
		byte[] inputBytes = new byte[GHashAlgorithmCore.BlockSizeInBytes];
		byte[] keyBytes = new byte[GHashAlgorithmCore.BlockSizeInBytes];

		for (int i = 0; i < 256; ++i)
		{
			random.NextBytes(inputBytes);
			random.NextBytes(keyBytes);
			await AssertSoftwareMultipliersMatchReference(BinaryPrimitives.ReadUInt128BigEndian(inputBytes), BinaryPrimitives.ReadUInt128BigEndian(keyBytes));
		}
	}

	[Test]
	[Arguments(16)]
	[Arguments(32)]
	[Arguments(64)]
	[Arguments(1024)]
	public async Task SoftwareMaximumCarryMatchesReference(int length)
	{
		byte[] key = new byte[GHashAlgorithmCore.BlockSizeInBytes];
		byte[] source = new byte[length];
		key.AsSpan().Fill(0xff);
		source.AsSpan().Fill(0xff);
		Vector128<byte> expected = ComputeReferenceHash(key, source, default, default);

		await Assert.That(HashSoftwarePaddedSegments(key, source, default, default)).IsEqualTo(expected);

		if (GHashNeon.IsSupported)
		{
			await Assert.That(HashNeonPaddedSegments(key, source, default, default)).IsEqualTo(expected);
		}
	}

	[Test]
	public async Task SoftwareSingleBitsMatchReference()
	{
		byte[] allOnes = new byte[GHashAlgorithmCore.BlockSizeInBytes];
		allOnes.AsSpan().Fill(0xff);

		for (int bit = 0; bit < 128; ++bit)
		{
			byte[] singleBit = new byte[GHashAlgorithmCore.BlockSizeInBytes];
			singleBit[bit / 8] = (byte)(1 << bit % 8);
			Vector128<byte> expectedDataBit = ComputeReferenceHash(allOnes, singleBit, default, default);
			Vector128<byte> expectedKeyBit = ComputeReferenceHash(singleBit, allOnes, default, default);

			await Assert.That(HashSoftwarePaddedSegments(allOnes, singleBit, default, default)).IsEqualTo(expectedDataBit);
			await Assert.That(HashSoftwarePaddedSegments(singleBit, allOnes, default, default)).IsEqualTo(expectedKeyBit);

			if (GHashNeon.IsSupported)
			{
				await Assert.That(HashNeonPaddedSegments(allOnes, singleBit, default, default)).IsEqualTo(expectedDataBit);
				await Assert.That(HashNeonPaddedSegments(singleBit, allOnes, default, default)).IsEqualTo(expectedKeyBit);
			}
		}
	}

	[Test]
	public async Task SoftwareRandomKeysAndSegmentsMatchReference()
	{
		Random random = new(0x63746d75);

		for (int i = 0; i < 128; ++i)
		{
			byte[] key = new byte[GHashAlgorithmCore.BlockSizeInBytes];
			byte[] first = new byte[random.Next(258)];
			byte[] second = new byte[random.Next(130)];
			byte[] third = new byte[random.Next(34)];
			random.NextBytes(key);
			random.NextBytes(first);
			random.NextBytes(second);
			random.NextBytes(third);
			Vector128<byte> expected = ComputeReferenceHash(key, first, second, third);

			await Assert.That(HashSoftwarePaddedSegments(key, first, second, third)).IsEqualTo(expected);

			if (GHashNeon.IsSupported)
			{
				await Assert.That(HashNeonPaddedSegments(key, first, second, third)).IsEqualTo(expected);
			}
		}
	}

	[Test]
	[MethodDataSource(nameof(BoundaryLengths))]
	public async Task SoftwareContinuationMatchesReference(int length)
	{
		byte[] key = CreateDeterministicSource(GHashAlgorithmCore.BlockSizeInBytes);
		byte[] first = CreateDeterministicSource(length);
		byte[] second = CreateDeterministicSource(17);
		byte[] third = CreateDeterministicSource(31);
		Vector128<byte> accumulator = HashSoftwarePaddedSegments(key, first, default, default);
		Vector128<byte> neonAccumulator = GHashNeon.IsSupported ? HashNeonPaddedSegments(key, first, default, default) : default;
		Vector128<byte> expectedPrefix = ComputeReferenceHash(key, first, default, default);
		Vector128<byte> expected = ComputeReferenceHash(key, first, second, third);
		GHashKey keyContext = GHashKey.Create(key);

		try
		{
			GHashSoftware.AppendPaddedSegments(ref accumulator, in keyContext.Value, default, default, default);
			await Assert.That(accumulator).IsEqualTo(expectedPrefix);
			GHashSoftware.AppendPaddedSegments(ref accumulator, in keyContext.Value, default, second, third);

			if (GHashNeon.IsSupported)
			{
				GHashNeon.AppendPaddedSegments(ref neonAccumulator, in keyContext.Value, default, default, default);
				await Assert.That(neonAccumulator).IsEqualTo(expectedPrefix);
				GHashNeon.AppendPaddedSegments(ref neonAccumulator, in keyContext.Value, default, second, third);
			}
		}
		finally
		{
			keyContext.Dispose();
		}

		await Assert.That(accumulator).IsEqualTo(expected);

		if (GHashNeon.IsSupported)
		{
			await Assert.That(neonAccumulator).IsEqualTo(expected);
		}
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
		await Assert.That(HashSoftwarePaddedSegments(key, first, second, third)).IsEqualTo(expected);

		if (GHashNeon.IsSupported)
		{
			await Assert.That(HashNeonPaddedSegments(key, first, second, third)).IsEqualTo(expected);
		}
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
		await Assert.That(HashSoftwarePaddedSegments(key, first, second, default)).IsEqualTo(segmentedHash);
		await Assert.That(HashSoftwarePaddedSegments(key, combined, default, default)).IsEqualTo(combinedHash);

		if (GHashNeon.IsSupported)
		{
			await Assert.That(HashNeonPaddedSegments(key, first, second, default)).IsEqualTo(segmentedHash);
			await Assert.That(HashNeonPaddedSegments(key, combined, default, default)).IsEqualTo(combinedHash);
		}
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
		Vector128<byte> softwareActual = HashSoftwarePaddedSegments(key, first, second, third);
		Vector128<byte> neonActual = GHashNeon.IsSupported ? HashNeonPaddedSegments(key, first, second, third) : default;

		await Assert.That(actual).IsEqualTo(expected);
		await Assert.That(softwareActual).IsEqualTo(expected);

		if (GHashNeon.IsSupported)
		{
			await Assert.That(neonActual).IsEqualTo(expected);
		}
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

	private static async Task AssertSoftwareMultipliersMatchReference(UInt128 input, UInt128 key)
	{
		ulong high32 = (ulong)(input >> 64);
		ulong low32 = (ulong)input;
		ulong high64 = high32;
		ulong low64 = low32;
		ulong keyHigh = (ulong)(key >> 64);
		ulong keyLow = (ulong)key;
		UInt128 expected = Multiply(input, key);

		GHashSoftware.Multiply32(ref high32, ref low32, keyHigh, keyLow);
		GHashSoftware.InitializeKey64(ref keyHigh, ref keyLow);
		GHashSoftware.Multiply64(ref high64, ref low64, keyHigh, keyLow);

		await Assert.That((UInt128)high32 << 64 | low32).IsEqualTo(expected);
		await Assert.That((UInt128)high64 << 64 | low64).IsEqualTo(expected);
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

	private static Vector128<byte> HashSoftwarePaddedSegments(ReadOnlySpan<byte> key, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> third)
	{
		GHashKey keyContext = GHashKey.Create(key);

		try
		{
			Vector128<byte> accumulator = default;
			GHashSoftware.AppendPaddedSegments(ref accumulator, in keyContext.Value, first, second, third);
			return accumulator;
		}
		finally
		{
			keyContext.Dispose();
		}
	}

	private static Vector128<byte> HashNeonPaddedSegments(ReadOnlySpan<byte> key, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> third)
	{
		GHashKey keyContext = GHashKey.Create(key);

		try
		{
			Vector128<byte> accumulator = default;
			GHashNeon.AppendPaddedSegments(ref accumulator, in keyContext.Value, first, second, third);
			return accumulator;
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
