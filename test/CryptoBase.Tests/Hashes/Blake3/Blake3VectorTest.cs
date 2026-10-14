using CryptoBase.Hashes.Blake3;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Blake3;

public class Blake3VectorTest
{
	private static readonly int[] Boundaries = [0, 1, 31, 32, 33, 63, 64, 65, 127, 128, 129, 130, Blake3TestVectors.OutputLength];

	private static readonly int[] PieceLengths = [1, 7, 63, 64, 65, 1023, 1024, 1025, 3072, 4097, 9000];

	public static IEnumerable<int> InputLengths => Blake3TestVectors.InputLengths;

	[Test]
	[CombinedDataSources]
	public async Task OneShotMatches([MethodDataSource(nameof(InputLengths))] int inputLength, [MethodDataSource(typeof(Blake3TestUtils), nameof(Blake3TestUtils.Modes))] Blake3Mode mode)
	{
		byte[] input = Blake3TestVectors.CreateInput(inputLength);
		byte[] expected = Blake3TestVectors.GetExpected(mode, inputLength);

		foreach (int length in Boundaries)
		{
			byte[] destination = new byte[length + 1];
			PrepareDestination(destination);
			Blake3TestUtils.HashData(mode, input, destination.AsSpan(0, length));
			await AssertOutput(destination, expected.AsSpan(0, length).ToArray());
		}
	}

	[Test]
	[CombinedDataSources]
	public async Task IncrementalMatches([MethodDataSource(nameof(InputLengths))] int inputLength, [MethodDataSource(typeof(Blake3TestUtils), nameof(Blake3TestUtils.Modes))] Blake3Mode mode)
	{
		byte[] input = Blake3TestVectors.CreateInput(inputLength);
		byte[] expected = Blake3TestVectors.GetExpected(mode, inputLength);
		using Blake3HashAlgorithm hasher = Blake3TestUtils.CreateHasher(mode);

		hasher.Append(input);
		await Blake3TestUtils.VerifyCurrentHash(hasher, expected);

		foreach (int pieceLength in PieceLengths)
		{
			hasher.Reset();
			HashAlgorithmTestUtils.AppendInPieces(hasher, input, pieceLength);
			await Blake3TestUtils.VerifyCurrentHash(hasher, expected);
		}

		hasher.Reset();
		HashAlgorithmTestUtils.AppendInPseudoRandomPieces(hasher, input, (uint)inputLength, 3 * 1024);
		await Blake3TestUtils.VerifyCurrentHash(hasher, expected);
	}

	[Test]
	[CombinedDataSources]
	public async Task SeekMatches([MethodDataSource(nameof(InputLengths))] int inputLength, [MethodDataSource(typeof(Blake3TestUtils), nameof(Blake3TestUtils.Modes))] Blake3Mode mode)
	{
		byte[] expected = Blake3TestVectors.GetExpected(mode, inputLength);
		byte[] destination = new byte[expected.Length + 1];
		using Blake3HashAlgorithm hasher = Blake3TestUtils.CreateHasher(mode);
		hasher.Append(Blake3TestVectors.CreateInput(inputLength));

		foreach (int position in Boundaries)
		{
			int remaining = expected.Length - position;

			foreach (int length in new[] { remaining, Math.Min(1, remaining), Math.Min(64, remaining) })
			{
				PrepareDestination(destination);
				hasher.GetCurrentHash(destination.AsSpan(0, length), (ulong)position);
				await AssertOutput(destination, expected.AsSpan(position, length).ToArray());
			}
		}
	}
}
