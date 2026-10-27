using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes.Blake2;
using CryptoBase.Hashes.MD5;
using CryptoBase.Hashes.Sha1;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Hashes.Sha3;
using CryptoBase.Hashes.SM3;
using CryptoBase.Tests.Hashes.Blake2;
using CryptoBase.Tests.Hashes.Sha2;
using CryptoBase.Tests.Hashes.Sha3;
using CryptoBase.Tests.Hashes.SM3;
using System.Security.Cryptography;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;
using BclMD5 = System.Security.Cryptography.MD5;

namespace CryptoBase.Tests.Hashes;

// Checks each core against the platform where it has the hash, the known digests of the core's test class where it has not, and SHA-3 against Sha3TestUtils.Hash.
[GenerateGenericTest(typeof(MD5Core))]
[GenerateGenericTest(typeof(Sha1Core))]
[GenerateGenericTest(typeof(Sha224Core))]
[GenerateGenericTest(typeof(Sha256Core))]
[GenerateGenericTest(typeof(Sha384Core))]
[GenerateGenericTest(typeof(Sha512Core))]
[GenerateGenericTest(typeof(SM3Core))]
[GenerateGenericTest(typeof(Blake2b256Core))]
[GenerateGenericTest(typeof(Blake2b512Core))]
[GenerateGenericTest(typeof(Sha3_224Core))]
[GenerateGenericTest(typeof(Sha3_256Core))]
[GenerateGenericTest(typeof(Sha3_384Core))]
[GenerateGenericTest(typeof(Sha3_512Core))]
public class HashCoreTest<T> where T : unmanaged, IHashCore<T>
{
	private static readonly (int BlockSize, IEnumerable<int> BoundaryLengths, Func<byte[], byte[]> Oracle) Case = typeof(T).Name switch
	{
		nameof(MD5Core) => PlatformCase(64, BclMD5.HashData),
		nameof(Sha1Core) => PlatformCase(64, SHA1.HashData),
		nameof(Sha224Core) => KnownCase(64, Sha224Test.BoundaryVectors),
		nameof(Sha256Core) => PlatformCase(64, SHA256.HashData),
		nameof(Sha384Core) => PlatformCase(128, SHA384.HashData),
		nameof(Sha512Core) => PlatformCase(128, SHA512.HashData),
		nameof(SM3Core) => KnownCase(64, SM3Test.BoundaryVectors),
		nameof(Blake2b256Core) => KnownCase(128, Blake2b256Test.BoundaryVectors),
		nameof(Blake2b512Core) => KnownCase(128, Blake2b512Test.BoundaryVectors),
		nameof(Sha3_224Core) => Sha3Case(28),
		nameof(Sha3_256Core) => Sha3Case(32),
		nameof(Sha3_384Core) => Sha3Case(48),
		nameof(Sha3_512Core) => Sha3Case(64),
		_ => throw new NotSupportedException(typeof(T).Name)
	};

	public static IEnumerable<int> BoundaryLengths => Case.BoundaryLengths;

	public static IEnumerable<(int, int, int)> IncrementalBatchCases => HashIncrementalBatchCases(Case.BlockSize);

	[Test]
	[MethodDataSource(nameof(BoundaryLengths))]
	public Task BlockBoundaries(int length)
	{
		return VerifyBoundary<T>(length, Case.Oracle);
	}

	[Test]
	[MethodDataSource(nameof(IncrementalBatchCases))]
	public Task IncrementalBlockBatches(int length, int sourceOffset, int blockSize)
	{
		return VerifyIncrementalBlockBatch<T>(length, sourceOffset, blockSize, Case.Oracle);
	}

	[Test]
	[CombinedDataSources]
	public Task InputIsUnchanged([MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(InputIntegrityLengths))] int length, [Arguments(1, 7)] int offset)
	{
		return VerifyInputIsUnchanged<T>(length, offset);
	}

	private static (int, IEnumerable<int>, Func<byte[], byte[]>) PlatformCase(int blockSize, Func<byte[], byte[]> oracle)
	{
		return (blockSize, BlockAndPaddingLengths(blockSize), oracle);
	}

	// The vectors also cover the lengths of IncrementalBatchCases.
	private static (int, IEnumerable<int>, Func<byte[], byte[]>) KnownCase(int blockSize, IEnumerable<(int Length, string ExpectedHex)> vectors)
	{
		(int Length, string ExpectedHex)[] known = [.. vectors];
		return (blockSize, known.Select(static vector => vector.Length), source => GetKnownDigest(source, known));
	}

	private static (int, IEnumerable<int>, Func<byte[], byte[]>) Sha3Case(int hashLength)
	{
		int rate = KeccakReference.Sha3Rate(hashLength);
		return (rate, RateBlockAndPaddingLengths(rate), source => Sha3TestUtils.Hash(hashLength, source));
	}
}
