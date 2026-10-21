using CryptoBase.Abstractions.Hashes;
using CryptoBase.Abstractions.Macs;
using CryptoBase.Hashes.Blake2b;
using CryptoBase.Hashes.Sha256;
using CryptoBase.Macs.Hmac;
using CryptoBase.Platform;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Macs.Hmac;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class HmacTest
{
	[Test]
	public Task Sha256LifecycleContract()
	{
		return VerifyLifecycleContract<HmacAlgorithm<Sha256HashAlgorithm>>();
	}

	[Test]
	public Task Sha256OwnershipContract()
	{
		return VerifyOwnershipContract<HmacAlgorithm<Sha256HashAlgorithm>>();
	}

	[Test]
	public Task ShortDestinationsDoNotChangeStateOrOutput()
	{
		return VerifyShortDestinations<HmacAlgorithm<Sha256HashAlgorithm>>();
	}

	[Test]
	[Arguments(0)]
	[Arguments(97)]
	public Task OneShotMacSupportsOverlappingInputsAndDestination(int destinationOffset)
	{
		return VerifyOneShotOverlap<HmacAlgorithm<Sha256HashAlgorithm>, PlatformHmacSha256>(destinationOffset);
	}

	internal static async Task VerifyOneShotOverlap<TMac, TReference>(int destinationOffset) where TMac : IOneShotMacAlgorithm where TReference : IOneShotMacAlgorithm
	{
		const int keyOffset = 0;
		const int keyLength = 64;
		const int sourceOffset = 80;
		const int sourceLength = 97;
		int bufferLength = Math.Max(sourceOffset + sourceLength, destinationOffset + TMac.MacLength);
		byte[] buffer = CreateDeterministicSource(bufferLength);
		byte[] expected = new byte[TReference.MacLength];
		TReference.Mac(buffer.AsSpan(keyOffset, keyLength), buffer.AsSpan(sourceOffset, sourceLength), expected);

		int written = TMac.Mac(buffer.AsSpan(keyOffset, keyLength), buffer.AsSpan(sourceOffset, sourceLength), buffer.AsSpan(destinationOffset, TMac.MacLength));

		await Assert.That(written).IsEqualTo(TMac.MacLength);
		await Assert.That(buffer.AsSpan(destinationOffset, written).ToArray()).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	public async Task Blake2bPrecompressedKeyBlocksMatchOneShot()
	{
		await VerifyReusedInstance<Blake2b512HashAlgorithm>();
		await VerifyReusedInstance<Blake2b256HashAlgorithm>();
	}

	private static async Task VerifyReusedInstance<THash>() where THash : unmanaged, IHmacHashCore<THash>
	{
		byte[] key = CreateDeterministicSource(32);
		byte[] source = CreateDeterministicSource(300);
		byte[] expected = new byte[HmacAlgorithm<THash>.MacLength];
		byte[] actual = new byte[HmacAlgorithm<THash>.MacLength];
		using HmacAlgorithm<THash> mac = HmacAlgorithm<THash>.Create(key);

		foreach (int length in (int[])[0, 1, 64, 127, 128, 129, 0, 255, 256, 257, 300, 0])
		{
			byte[] message = source.AsSpan(0, length).ToArray();
			HmacAlgorithm<THash>.Mac(key, message, expected);

			mac.Append(message.AsSpan().Slice(0, length / 2));
			mac.Append(message.AsSpan().Slice(length / 2));
			mac.GetCurrentMac(actual);
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);

			mac.GetMacAndReset(actual);
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);

			mac.Append(message);
			mac.Reset();
		}

		mac.GetMacAndReset(actual);
		HmacAlgorithm<THash>.Mac(key, ReadOnlySpan<byte>.Empty, expected);
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	internal static async Task VerifyLifecycleContract<TMac>() where TMac : class, IMacAlgorithm<TMac>
	{
		byte[] key = CreateDeterministicSource(137);
		byte[] source = CreateDeterministicSource(173);
		byte[] expected = new byte[TMac.MacLength];
		byte[] prefixExpected = new byte[TMac.MacLength];
		byte[] destination = new byte[TMac.MacLength + 1];
		_ = TMac.Mac(key, source, expected);
		int split = source.Length / 2;
		_ = TMac.Mac(key, source.AsSpan().Slice(0, split), prefixExpected);

		using TMac macAlgorithm = TMac.Create(key);
		macAlgorithm.Append(source.AsSpan().Slice(0, split));
		PrepareDestination(destination);
		int written = macAlgorithm.GetCurrentMac(destination);
		await AssertOutput(destination, prefixExpected, written);

		macAlgorithm.Append(source.AsSpan().Slice(split));
		PrepareDestination(destination);
		written = macAlgorithm.GetCurrentMac(destination);
		await AssertOutput(destination, expected, written);
		PrepareDestination(destination);
		written = macAlgorithm.GetCurrentMac(destination);
		await AssertOutput(destination, expected, written);
		PrepareDestination(destination);
		written = macAlgorithm.GetMacAndReset(destination);
		await AssertOutput(destination, expected, written);

		macAlgorithm.Append(source);
		PrepareDestination(destination);
		written = macAlgorithm.GetMacAndReset(destination);
		await AssertOutput(destination, expected, written);

		macAlgorithm.Append(CreateDeterministicSource(17));
		macAlgorithm.Reset();
		macAlgorithm.Append(source);
		PrepareDestination(destination);
		written = macAlgorithm.GetMacAndReset(destination);
		await AssertOutput(destination, expected, written);
	}

	internal static async Task VerifyOwnershipContract<TMac>() where TMac : class, IMacAlgorithm<TMac>
	{
		byte[] key = CreateDeterministicSource(37);
		byte[] source = CreateDeterministicSource(19);
		byte[] destination = new byte[TMac.MacLength];

		using TMac owner = TMac.Create(key);
		TMac alias = owner;
		alias.Dispose();
		alias.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(() => owner.Append(source)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(owner.Reset).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => owner.GetCurrentMac(destination)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => owner.GetMacAndReset(destination)).ThrowsExactly<ObjectDisposedException>();
		}
	}

	internal static async Task VerifyShortDestinations<TMac>() where TMac : class, IMacAlgorithm<TMac>
	{
		byte[] key = CreateDeterministicSource(137);
		byte[] source = CreateDeterministicSource(73);
		byte[] expected = new byte[TMac.MacLength];
		TMac.Mac(key, source, expected);
		byte[] shortDestination = new byte[TMac.MacLength - 1];
		byte[] destination = new byte[TMac.MacLength + 1];
		using TMac macAlgorithm = TMac.Create(key);
		macAlgorithm.Append(source);

		PrepareDestination(shortDestination);
		await Assert.That(() => macAlgorithm.GetCurrentMac(shortDestination)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
		await Assert.That(shortDestination).All(static value => value is DestinationSentinel);
		PrepareDestination(destination);
		int written = macAlgorithm.GetCurrentMac(destination);
		await AssertOutput(destination, expected, written);

		PrepareDestination(shortDestination);
		await Assert.That(() => macAlgorithm.GetMacAndReset(shortDestination)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
		await Assert.That(shortDestination).All(static value => value is DestinationSentinel);
		PrepareDestination(destination);
		written = macAlgorithm.GetMacAndReset(destination);
		await AssertOutput(destination, expected, written);

		byte[] keyCopy = (byte[])key.Clone();
		byte[] sourceCopy = (byte[])source.Clone();
		PrepareDestination(shortDestination);
		await Assert.That(() => TMac.Mac(key, source, shortDestination)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
		await Assert.That(shortDestination).All(static value => value is DestinationSentinel);
		await Assert.That(key).IsEquivalentTo(keyCopy, CollectionOrdering.Matching);
		await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);
	}
}
