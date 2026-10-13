using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha256;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class HashAlgorithmTest
{
	[Test]
	public async Task LifecycleContract()
	{
		byte[] source = "abc"u8.ToArray();
		byte[] expected = SHA256.HashData(source);
		byte[] emptyExpected = SHA256.HashData(ReadOnlySpan<byte>.Empty);
		byte[] doubledExpected = SHA256.HashData(Concat(source, source));

		await Assert.That(Sha256HashAlgorithm.HashLength).IsEqualTo(expected.Length);

		byte[] destination = CreateDestination<Sha256HashAlgorithm>();
		using HashAlgorithm<Sha256HashAlgorithm> hashAlgorithm = HashAlgorithm<Sha256HashAlgorithm>.Create();

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
	}

	[Test]
	[Arguments(0, 0)]
	[Arguments(0, 17)]
	[Arguments(17, 0)]
	public async Task HashDataSupportsOverlappingSourceAndDestination(int sourceOffset, int destinationOffset)
	{
		const int sourceLength = 97;
		int bufferLength = Math.Max(sourceOffset + sourceLength, destinationOffset + Sha256HashAlgorithm.HashLength);
		byte[] buffer = CreateDeterministicSource(bufferLength);
		byte[] expected = SHA256.HashData(buffer.AsSpan().Slice(sourceOffset, sourceLength));

		int written = HashAlgorithm<Sha256HashAlgorithm>.HashData(buffer.AsSpan().Slice(sourceOffset, sourceLength), buffer.AsSpan().Slice(destinationOffset, Sha256HashAlgorithm.HashLength));

		await Assert.That(written).IsEqualTo(Sha256HashAlgorithm.HashLength);
		await Assert.That(buffer.AsSpan().Slice(destinationOffset, written).ToArray()).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	public async Task OwnershipContract()
	{
		byte[] source = CreateDeterministicSource(19);
		byte[] destination = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength];

		using HashAlgorithm<Sha256HashAlgorithm> owner = HashAlgorithm<Sha256HashAlgorithm>.Create();
		HashAlgorithm<Sha256HashAlgorithm> alias = owner;
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
	public async Task ShortDestinationsLeaveDestinationAndStateUnchanged()
	{
		byte[] source = CreateDeterministicSource(23);
		byte[] expected = SHA256.HashData(source);
		byte[] emptyExpected = SHA256.HashData(ReadOnlySpan<byte>.Empty);
		byte[] shortDestination = new byte[Sha256HashAlgorithm.HashLength - 1];
		byte[] destination = CreateDestination<Sha256HashAlgorithm>();

		using HashAlgorithm<Sha256HashAlgorithm> hashAlgorithm = HashAlgorithm<Sha256HashAlgorithm>.Create();
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
		await Assert.That(() => HashAlgorithm<Sha256HashAlgorithm>.HashData(source, shortDestination)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
		await Assert.That(shortDestination).All(static value => value is DestinationSentinel);
		await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);
	}
}
