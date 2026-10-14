using CryptoBase.Hashes.Blake3;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Blake3;

public enum Blake3Mode
{
	Hash,
	KeyedHash,
	DeriveKey
}

internal static class Blake3TestUtils
{
	public static IEnumerable<Blake3Mode> Modes => Enum.GetValues<Blake3Mode>();

	public static Blake3HashAlgorithm CreateHasher(Blake3Mode mode)
	{
		return mode switch
		{
			Blake3Mode.Hash => Blake3HashAlgorithm.Create(),
			Blake3Mode.KeyedHash => Blake3HashAlgorithm.CreateKeyed(Blake3TestVectors.Key),
			Blake3Mode.DeriveKey => Blake3HashAlgorithm.CreateDeriveKey(Blake3TestVectors.Context),
			_ => throw new ArgumentOutOfRangeException(nameof(mode))
		};
	}

	public static void HashData(Blake3Mode mode, ReadOnlySpan<byte> source, Span<byte> destination, int maxDegreeOfParallelism = 1)
	{
		switch (mode)
		{
			case Blake3Mode.Hash:
			{
				Blake3HashAlgorithm.HashData(source, destination, maxDegreeOfParallelism);
				break;
			}
			case Blake3Mode.KeyedHash:
			{
				Blake3HashAlgorithm.KeyedHashData(Blake3TestVectors.Key, source, destination, maxDegreeOfParallelism);
				break;
			}
			case Blake3Mode.DeriveKey:
			{
				Blake3HashAlgorithm.DeriveKey(Blake3TestVectors.Context, source, destination, maxDegreeOfParallelism);
				break;
			}
			default:
			{
				throw new ArgumentOutOfRangeException(nameof(mode));
			}
		}
	}

	public static byte[] HashData(Blake3Mode mode, ReadOnlySpan<byte> source, int outputLength, int maxDegreeOfParallelism = 1)
	{
		byte[] output = new byte[outputLength];
		HashData(mode, source, output, maxDegreeOfParallelism);
		return output;
	}

	public static Blake3Reference CreateReference(Blake3Mode mode)
	{
		return mode switch
		{
			Blake3Mode.Hash => Blake3Reference.Create(),
			Blake3Mode.KeyedHash => Blake3Reference.CreateKeyed(Blake3TestVectors.Key),
			Blake3Mode.DeriveKey => Blake3Reference.CreateDeriveKey(Blake3TestVectors.Context),
			_ => throw new ArgumentOutOfRangeException(nameof(mode))
		};
	}

	public static byte[] ReferenceHash(Blake3Mode mode, ReadOnlySpan<byte> source, int outputLength, ulong position = 0)
	{
		Blake3Reference reference = CreateReference(mode);
		reference.Update(source);
		byte[] output = new byte[outputLength];
		reference.Finalize(output, position);
		return output;
	}

	public static async Task VerifyCurrentHash(Blake3HashAlgorithm hasher, byte[] expected)
	{
		byte[] destination = new byte[expected.Length + 1];
		PrepareDestination(destination);
		hasher.GetCurrentHash(destination.AsSpan(0, expected.Length));
		await AssertOutput(destination, expected);

		int prefixLength = Math.Min(expected.Length, Blake3HashAlgorithm.HashLength);
		PrepareDestination(destination);
		hasher.GetCurrentHash(destination.AsSpan(0, prefixLength));
		await AssertOutput(destination, expected.AsSpan(0, prefixLength).ToArray());
	}
}
