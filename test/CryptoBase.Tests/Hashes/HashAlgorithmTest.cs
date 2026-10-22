using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha2;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class HashAlgorithmTest
{
	[Test]
	public Task LifecycleContract()
	{
		return VerifyLifecycleContract<HashAlgorithm<Sha256Core>>(SHA256.HashData);
	}

	[Test]
	[Arguments(0, 0)]
	[Arguments(0, 17)]
	[Arguments(17, 0)]
	public async Task HashDataSupportsOverlappingSourceAndDestination(int sourceOffset, int destinationOffset)
	{
		const int sourceLength = 97;
		int bufferLength = Math.Max(sourceOffset + sourceLength, destinationOffset + Sha256Core.HashLength);
		byte[] buffer = CreateDeterministicSource(bufferLength);
		byte[] expected = SHA256.HashData(buffer.AsSpan().Slice(sourceOffset, sourceLength));

		int written = HashAlgorithm<Sha256Core>.HashData(buffer.AsSpan().Slice(sourceOffset, sourceLength), buffer.AsSpan().Slice(destinationOffset, Sha256Core.HashLength));

		await Assert.That(written).IsEqualTo(Sha256Core.HashLength);
		await Assert.That(buffer.AsSpan().Slice(destinationOffset, written).ToArray()).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	public Task OwnershipContract()
	{
		return VerifyOwnershipContract<HashAlgorithm<Sha256Core>>();
	}

	[Test]
	public Task ShortDestinationsLeaveDestinationAndStateUnchanged()
	{
		return VerifyShortDestinations<HashAlgorithm<Sha256Core>>(SHA256.HashData);
	}

	internal static async Task VerifyLifecycleContract<TAlgorithm>(Func<byte[], byte[]> oracle) where TAlgorithm : class, IHashAlgorithm<TAlgorithm>
	{
		byte[] source = "abc"u8.ToArray();
		byte[] expected = oracle(source);
		byte[] emptyExpected = oracle([]);
		byte[] doubledExpected = oracle(Concat(source, source));

		await Assert.That(TAlgorithm.HashLength).IsEqualTo(expected.Length);

		byte[] destination = HashAlgorithmTestUtils<TAlgorithm>.CreateDestination();
		using TAlgorithm hashAlgorithm = TAlgorithm.Create();

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
		written = hashAlgorithm.GetCurrentHash(destination);
		await AssertOutput(destination, expected, written);

		PrepareDestination(destination);
		written = hashAlgorithm.GetHashAndReset(destination);
		await AssertOutput(destination, expected, written);
	}

	internal static async Task VerifyOwnershipContract<TAlgorithm>() where TAlgorithm : class, IHashAlgorithm<TAlgorithm>
	{
		byte[] source = CreateDeterministicSource(19);
		byte[] destination = new byte[TAlgorithm.HashLength];

		using TAlgorithm owner = TAlgorithm.Create();
		TAlgorithm alias = owner;
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

	internal static async Task VerifyShortDestinations<TAlgorithm>(Func<byte[], byte[]> oracle) where TAlgorithm : class, IHashAlgorithm<TAlgorithm>
	{
		byte[] source = CreateDeterministicSource(23);
		byte[] expected = oracle(source);
		byte[] emptyExpected = oracle([]);
		byte[] shortDestination = new byte[TAlgorithm.HashLength - 1];
		byte[] destination = HashAlgorithmTestUtils<TAlgorithm>.CreateDestination();

		using TAlgorithm hashAlgorithm = TAlgorithm.Create();
		hashAlgorithm.Append(source);
		PrepareDestination(shortDestination);

		await Assert.That(() => hashAlgorithm.GetCurrentHash(shortDestination)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
		await Assert.That(shortDestination).All(static value => value is DestinationSentinel);

		PrepareDestination(destination);
		int written = hashAlgorithm.GetCurrentHash(destination);
		await AssertOutput(destination, expected, written);

		hashAlgorithm.Reset();
		hashAlgorithm.Append(source);
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
		await Assert.That(() => TAlgorithm.HashData(source, shortDestination)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
		await Assert.That(shortDestination).All(static value => value is DestinationSentinel);
		await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);
	}
}
