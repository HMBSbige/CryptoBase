using CryptoBase.IO;
using CryptoBase.Platform;
using CryptoBase.Tests.Hashes;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;
using ManagedSha256 = CryptoBase.Hashes.HashAlgorithm<CryptoBase.Hashes.Sha2.Sha256Core>;

namespace CryptoBase.Tests.Platform;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class PlatformSha256Test
{
	// FIPS 180-2, appendix B
	[Test]
	[Arguments(@"", @"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
	[Arguments(@"abc", @"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
	[Arguments(@"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", @"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")]
	public async Task Vector(string value, string expected)
	{
		await HashAlgorithmTestUtils<ManagedSha256>.VerifyHashVector(value, expected, 32);
		await HashAlgorithmTestUtils<PlatformSha256>.VerifyHashVector(value, expected, 32);
	}

	[Test]
	public async Task IsPreferredOnlyWithX86ShaExtensions()
	{
		bool expected = X86Base.IsSupported && (X86Base.CpuId(7, 0).Ebx & 1 << 29) is not 0;
		await Assert.That(PlatformSha256.IsPreferred).IsEqualTo(expected);
	}

	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(HashAlgorithmTestUtils.Hash64BlockAndPaddingLengths))]
	public Task BlockBoundaries(int length)
	{
		return HashAlgorithmTestUtils<PlatformSha256>.VerifyBoundary(length, ManagedHash);
	}

	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(HashAlgorithmTestUtils.Hash64IncrementalBatchCases))]
	public Task IncrementalBlockBatches(int length, int sourceOffset, int blockSize)
	{
		return HashAlgorithmTestUtils<PlatformSha256>.VerifyIncrementalBlockBatch(length, sourceOffset, blockSize, ManagedHash);
	}

	[Test]
	[Arguments(1)]
	[Arguments(31)]
	[Arguments(32)]
	[Arguments(33)]
	[Arguments(97)]
	[Arguments(1025)]
	public Task HashDataSupportsOverlappingSourceAndDestination(int length)
	{
		byte[] source = CreateDeterministicSource(length);
		return HashAlgorithmTestUtils<PlatformSha256>.VerifyOverlappingHashData(source, ManagedHash(source));
	}

	[Test]
	[CombinedDataSources]
	public Task InputIsUnchanged([MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(HashAlgorithmTestUtils.InputIntegrityLengths))] int length, [Arguments(1, 7)] int offset)
	{
		return HashAlgorithmTestUtils<PlatformSha256>.VerifyInputIsUnchanged(length, offset);
	}

	[Test]
	public async Task LifecycleContract()
	{
		byte[] source = "abc"u8.ToArray();
		byte[] expected = ManagedHash(source);
		byte[] emptyExpected = ManagedHash([]);
		byte[] doubledExpected = ManagedHash(Concat(source, source));
		byte[] destination = HashAlgorithmTestUtils<PlatformSha256>.CreateDestination();

		using PlatformSha256 hashAlgorithm = PlatformSha256.Create();

		PrepareDestination(destination);
		int written = hashAlgorithm.GetCurrentHash(destination);
		await AssertOutput(destination, emptyExpected, written);

		int split = source.Length / 2;
		hashAlgorithm.Append(source.AsSpan().Slice(0, split));
		hashAlgorithm.Append(source.AsSpan().Slice(split));

		PrepareDestination(destination);
		written = hashAlgorithm.GetCurrentHash(destination);
		await AssertOutput(destination, expected, written);

		PrepareDestination(destination);
		written = hashAlgorithm.GetCurrentHash(destination);
		await AssertOutput(destination, expected, written);

		hashAlgorithm.Append(source);
		PrepareDestination(destination);
		written = hashAlgorithm.GetHashAndReset(destination);
		await AssertOutput(destination, doubledExpected, written);

		PrepareDestination(destination);
		written = hashAlgorithm.GetCurrentHash(destination);
		await AssertOutput(destination, emptyExpected, written);

		hashAlgorithm.Append(source);
		hashAlgorithm.Reset();
		PrepareDestination(destination);
		written = hashAlgorithm.GetCurrentHash(destination);
		await AssertOutput(destination, emptyExpected, written);

		hashAlgorithm.Append(source);
		PrepareDestination(destination);
		written = hashAlgorithm.GetHashAndReset(destination);
		await AssertOutput(destination, expected, written);
	}

	[Test]
	public async Task OwnershipContract()
	{
		byte[] source = CreateDeterministicSource(19);
		byte[] destination = new byte[PlatformSha256.HashLength];

		using PlatformSha256 owner = PlatformSha256.Create();
		PlatformSha256 alias = owner;
		alias.Dispose();
		alias.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(() => owner.Append(source)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(owner.Reset).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => owner.GetCurrentHash(destination)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => owner.GetHashAndReset(destination)).ThrowsExactly<ObjectDisposedException>();
		}
	}

	[Test]
	public async Task PlatformFailureDisposesTheInstance()
	{
		byte[] source = CreateDeterministicSource(19);
		byte[] destination = HashAlgorithmTestUtils<PlatformSha256>.CreateDestination();
		Action<PlatformSha256>[] operations =
		[
			hashAlgorithm => hashAlgorithm.Append(source),
			hashAlgorithm => hashAlgorithm.Reset(),
			hashAlgorithm => hashAlgorithm.GetCurrentHash(destination),
			hashAlgorithm => hashAlgorithm.GetHashAndReset(destination),
		];

		foreach (Action<PlatformSha256> operation in operations)
		{
			using IncrementalHash working = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
			using PlatformSha256 hashAlgorithm = PlatformSha256.Create();

			// Make the next platform call fail.
			PlatformFields.Hash(hashAlgorithm).Dispose();
			PrepareDestination(destination);
			await Assert.That(() => operation(hashAlgorithm)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(destination).All(static value => value is DestinationSentinel);

			// Working platform state does not revive the failed instance.
			PlatformFields.Hash(hashAlgorithm) = working;
			await Assert.That(() => hashAlgorithm.GetHashAndReset(destination)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(destination).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	public async Task ShortDestinationsLeaveDestinationAndStateUnchanged()
	{
		byte[] source = CreateDeterministicSource(23);
		byte[] expected = ManagedHash(source);
		byte[] emptyExpected = ManagedHash([]);
		byte[] shortDestination = new byte[PlatformSha256.HashLength - 1];
		byte[] destination = HashAlgorithmTestUtils<PlatformSha256>.CreateDestination();

		using PlatformSha256 hashAlgorithm = PlatformSha256.Create();
		hashAlgorithm.Append(source);
		PrepareDestination(shortDestination);

		await Assert.That(() => hashAlgorithm.GetCurrentHash(shortDestination)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
		await Assert.That(shortDestination).All(static value => value is DestinationSentinel);

		PrepareDestination(destination);
		int written = hashAlgorithm.GetCurrentHash(destination);
		await AssertOutput(destination, expected, written);

		PrepareDestination(shortDestination);
		await Assert.That(() => hashAlgorithm.GetHashAndReset(shortDestination)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
		await Assert.That(shortDestination).All(static value => value is DestinationSentinel);

		PrepareDestination(destination);
		written = hashAlgorithm.GetHashAndReset(destination);
		await AssertOutput(destination, expected, written);

		PrepareDestination(destination);
		written = hashAlgorithm.GetCurrentHash(destination);
		await AssertOutput(destination, emptyExpected, written);

		byte[] sourceCopy = (byte[])source.Clone();
		PrepareDestination(shortDestination);
		await Assert.That(() => PlatformSha256.HashData(source, shortDestination)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
		await Assert.That(shortDestination).All(static value => value is DestinationSentinel);
		await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);
	}

	[Test]
	public async Task HashStreamHashesTheBytesWritten()
	{
		byte[] source = CreateDeterministicSource(4099);
		byte[] expected = ManagedHash(source);
		using MemoryStream inner = new();
		using HashStream<PlatformSha256> hashing = HashStream.Create(inner, PlatformSha256.Create(), true);

		hashing.Write(source.AsSpan().Slice(0, 1000));
		hashing.Write(source.AsSpan().Slice(1000));

		byte[] actual = new byte[PlatformSha256.HashLength];
		int written = hashing.GetHashAndReset(actual);

		using (Assert.Multiple())
		{
			await Assert.That(written).IsEqualTo(expected.Length);
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(inner.ToArray()).IsEquivalentTo(source, CollectionOrdering.Matching);
		}
	}

	private static byte[] ManagedHash(byte[] source)
	{
		byte[] hash = new byte[ManagedSha256.HashLength];
		ManagedSha256.HashData(source, hash);
		return hash;
	}

	private static class PlatformFields
	{
		[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_hash")]
		public static extern ref IncrementalHash Hash(PlatformSha256 hashAlgorithm);
	}
}
