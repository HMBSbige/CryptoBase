using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes.Blake3;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Blake3;

public class Blake3Test
{
	public static IEnumerable<(int Length, string ExpectedHex)> BoundaryVectors =>
	[
		(0, @"af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
		(1, @"37b55d0bffa614d633d3fa9d9ba41b980d0f8acc6cdbf4f26e5dfcca452b8529"),
		(63, @"9c8fd6a29895ff09ca9ece26dfb167f06423f3d868ef7ee273467745343aabaa"),
		(64, @"5a172a2784f8f1573dd7eb7266bf69d68107e0bdeb9f206780ac9495c389e15e"),
		(65, @"f66b5cf96f73ae28a24fd3db6b6f083338974564affd6ac83cb8a880025d6ac3"),
		(1023, @"c5a6a00d933fae05fbf9c529771cd404371132390c9cbcca50cf1ae4680ead72"),
		(1024, @"b017ef5fc657b7dfff99ea58e6c8c5ceadcebe091567682530cb66a07fc8c94c"),
		(1025, @"8028e5c9f8a9df9c649631324b213d3c83da4cd3e7097b591a60203258d7cf62"),
		(2047, @"48a3963116dfe7dac839a2d8710e45588759b2b2be923d7920b3ebf90b669f35"),
		(2048, @"13000d1887c58975ccabfbffa762f8d55e8108cb7ede905699dbcf65ccb88dd8"),
		(2049, @"6ef580dd26fdffd1b53503315dbde827b633b6d26cd09aa1f0c2f3fbb8e0ba5f"),
		(3072, @"26ae7cb4acdb92c9038a7fe6e327de5e8ed6953f7401ea79c520732a332a88cd"),
		(3073, @"b607aacbe21e5c3035d5333d17bf661e376de1c642369039c10067c48016c4e6"),
		(4095, @"d07a19b5f341396ae1fdb700f4b1702be70f76abc1dea4d0194c040bc8199ba7"),
		(4096, @"7dc858af2878d69b8afda6b6cadabab4087613718cbafa093bdd8904d0e4ceec"),
		(4097, @"b7e4aaa3da97bf09f728c76ed55017d80f8d920c0c2d200493e0a2797aba9e11"),
		(8191, @"c1db0dbaf9df97da6792c0fab0db45aa0571fc944bc014d479167afe330685a0"),
		(8192, @"cead26eb7bfb51a0be5692c475734f855449557b46fd6cb7bb1f1d7106921914"),
		(8193, @"1ec2d24e3aa3306208a8b0eedeb3c13137d66631c0462c3929358b99421c0623"),
		(16383, @"dfb30cadb8c727b1cd1438a6401726bb9ff5f50302c7e2dae3d12e8b0b41dfe4"),
		(16384, @"9c4b788edf43771b5c6639b2dd4e826a7a41c4816290d8adf3d1ff139d7de259"),
		(16385, @"5df0e3089802f5ea1611621791d0a6c57fac41695896d8183f7534911e0cccb6"),
		(17407, @"14f4afc43135782a29f4d9cc796b562a627802c3970cdafd6bff3023159f993c"),
		(31745, @"9c35c7783d8b108634d4a2205b5ab59975b9a4ebc14afefc962bb7c3413ff3de"),
		(65535, @"4f5c035d293264884fee0a92c958da0d32bfe1178738a1982c8d73da9f2e2a83"),
		(65536, @"9d29fb090a7dbcdc5f97832ec431eb2d5d673d585e303254cc5611966520a2e8"),
		(65537, @"6ba0097adf171381a3b5e6d9d6810ed5244a981d02512b4b7a04ed57a0c63f73"),
		(66560, @"b057aace67ae083a0068064613e912f52b84d9ad98b46be72d3b346624469d10"),
		(131073, @"2db19e4fa8ae8401ed5e62aeb70d9519f4636c519cd14f9842bb8f03d949020c"),
		(1048575, @"d80f6906ee82672e7f1a734bde1f4782b16903889268c17ff36c72303ea3d8a9"),
		(1048576, @"8aa336a84180c403404b1845e68f8b6b09c33be6d849b3afe9fd122c76ff4237"),
		(1048577, @"3ad96e92557e26836e910003db01da1d61539ee5b00fe7cd9df8f3a620808570"),
		(1049601, @"cb28b1e45646b556afcc973ebe2ca55d204b2dfabfbb7f772be2bf6b9e5492d0"),
		(4194305, @"0eae828075680cd4dde0b137b5ba7ec21a20025dcd8c870f7bb5e39789e50746")
	];

	[Test]
	[Arguments("", "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")]
	[Arguments("abc", "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")]
	[Arguments("The quick brown fox jumps over the lazy dog", "2f1514181aadccd913abd94cfa592701a5686ab23f8df1dff1b74710febc6d4a")]
	public Task KnownVectors(string value, string expected)
	{
		return HashAlgorithmTestUtils<Blake3HashAlgorithm>.VerifyHashVector(value, expected, 32);
	}

	[Test]
	[MethodDataSource(nameof(BoundaryVectors))]
	public async Task TreeBoundaries(int length, string expectedHex)
	{
		await HashAlgorithmTestUtils<Blake3HashAlgorithm>.VerifyBoundary(length, expectedHex);

		using Blake3HashAlgorithm hasher = Blake3HashAlgorithm.Create();
		AppendInPieces(hasher, CreateDeterministicSource(length), 1024 * 5 + 3);
		await Blake3TestUtils.VerifyCurrentHash(hasher, Convert.FromHexString(expectedHex));
	}

	[Test]
	public async Task PiecewiseAppendsMatchOneShot()
	{
		int[][] sequences =
		[
			[1024],
			[1024, 1024],
			[1024, 1024, 1],
			[1023, 1, 0, 1024, 2049, 3],
			[100, 16284, 1, 16383, 16384, 16385, 2],
			[2048, 1024, 1024],
			[4096, 4096, 3072, 1024, 5120, 1]
		];

		foreach (int[] pieceLengths in sequences)
		{
			byte[] source = CreateDeterministicSource(pieceLengths.Sum());
			using Blake3HashAlgorithm hasher = Blake3HashAlgorithm.Create();
			int length = 0;

			foreach (int pieceLength in pieceLengths)
			{
				hasher.Append(source.AsSpan(length, pieceLength));
				length += pieceLength;

				byte[] actual = new byte[Blake3HashAlgorithm.HashLength];
				hasher.GetCurrentHash(actual);
				await Assert.That(actual).IsEquivalentTo(Blake3TestUtils.ReferenceHash(Blake3Mode.Hash, source.AsSpan(0, length), Blake3HashAlgorithm.HashLength), CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	[CombinedDataSources]
	public Task InputIsUnchanged([MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(InputIntegrityLengths))] int length, [Arguments(1, 7)] int offset)
	{
		return HashAlgorithmTestUtils<Blake3HashAlgorithm>.VerifyInputIsUnchanged(length, offset);
	}

	[Test]
	public async Task ShortDestinationsLeaveDestinationAndStateUnchanged()
	{
		byte[] source = CreateDeterministicSource(3000);
		byte[] expected = Blake3TestUtils.ReferenceHash(Blake3Mode.Hash, source, Blake3HashAlgorithm.HashLength);
		byte[] shortDestination = new byte[Blake3HashAlgorithm.HashLength - 1];
		byte[] destination = HashAlgorithmTestUtils<Blake3HashAlgorithm>.CreateDestination();

		using Blake3HashAlgorithm hasher = Blake3HashAlgorithm.Create();
		IHashAlgorithm<Blake3HashAlgorithm> hashAlgorithm = hasher;
		hashAlgorithm.Append(source);
		PrepareDestination(shortDestination);

		using (Assert.Multiple())
		{
			await Assert.That(() => hashAlgorithm.GetCurrentHash(shortDestination)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
			await Assert.That(() => hashAlgorithm.GetHashAndReset(shortDestination)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
			await Assert.That(() => HashData<Blake3HashAlgorithm>(source, shortDestination)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
			await Assert.That(shortDestination).All(static value => value is DestinationSentinel);
		}

		PrepareDestination(destination);
		int written = hashAlgorithm.GetHashAndReset(destination);
		await AssertOutput(destination, expected, written);
	}

	private static int HashData<TAlgorithm>(ReadOnlySpan<byte> source, Span<byte> destination) where TAlgorithm : IOneShotHashAlgorithm
	{
		return TAlgorithm.HashData(source, destination);
	}
}
