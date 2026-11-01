using CryptoBase.KeyAgreements.Xdh;
using System.Numerics;
using System.Reflection;
using System.Runtime.InteropServices;
using static CryptoBase.Tests.EllipticCurves.Curve25519.Curve25519Reference;
using static CryptoBase.Tests.KeyAgreements.KeyAgreementTestUtils;
using static CryptoBase.Tests.KeyAgreements.Xdh.X25519TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.KeyAgreements.Xdh;

// X25519 against the ladder of Curve25519Reference; the RFC 7748 and Wycheproof vectors are in their own tests.
public class X25519Test
{
	private const int Iterations = 8;

	private static readonly byte[] Nine = EncodeInteger(9);

	[Test]
	public async Task LengthsAreFixed()
	{
		await Assert.That((X25519.PrivateKeyLength, X25519.PublicKeyLength, X25519.SharedSecretLength)).IsEqualTo((32, 32, 32));
	}

	// Every 32 bytes are a private key, exported as they were imported; the bits that clamping overwrites do not change the public key.
	[Test]
	public async Task AnyPrivateKeyRoundTripsAndClampsWhenUsed()
	{
		Random random = new(1);
		List<byte[]> privateKeys = [new byte[32], Enumerable.Repeat((byte)0xFF, 32).ToArray(), Nine];

		for (int i = 0; i < Iterations; ++i)
		{
			privateKeys.Add(RandomBytes(random));
		}

		List<string> failures = [];

		foreach (byte[] privateKey in privateKeys)
		{
			using X25519 key = X25519.ImportPrivateKey(privateKey);
			byte[] flipped = (byte[])privateKey.Clone();
			flipped[0] ^= 0x07;
			flipped[31] ^= 0xC0;
			using X25519 clampedAlike = X25519.ImportPrivateKey(flipped);
			byte[] publicKey = ExportPublicKey(key);

			if (!ExportPrivateKey(key).AsSpan().SequenceEqual(privateKey) || !publicKey.AsSpan().SequenceEqual(X25519Function(privateKey, Nine)) || !ExportPublicKey(clampedAlike).AsSpan().SequenceEqual(publicKey))
			{
				failures.Add($"private key {Convert.ToHexString(privateKey)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Points of the curve and of the twist, and u-coordinates of p or more or with bit 255 set, which are reduced and masked.
	[Test]
	public async Task SharedSecretsMatchTheReference()
	{
		Random random = new(2);
		List<byte[]> peers = [EncodeInteger(P + 2), EncodeInteger((BigInteger.One << 255) - 1), Nine];

		for (int i = 0; i < 2 * Iterations; ++i)
		{
			byte[] peer = RandomBytes(random);
			peers.Add(peer);
		}

		List<string> failures = [];

		foreach (byte[] peer in peers)
		{
			byte[] privateKey = RandomBytes(random);
			using X25519 key = X25519.ImportPrivateKey(privateKey);
			byte[] masked = (byte[])peer.Clone();
			masked[31] ^= 0x80;
			byte[] expected = X25519Function(privateKey, peer);

			if (!DeriveSharedSecret(key, peer).AsSpan().SequenceEqual(expected) || !DeriveSharedSecret(key, masked).AsSpan().SequenceEqual(expected))
			{
				failures.Add($"peer {Convert.ToHexString(peer)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The reference gives 0 for these with any key, and nothing else does: the check depends on the peer key alone.
	[Test]
	public async Task SmallOrderPublicKeysReturnFalse()
	{
		Random random = new(3);
		byte[][] smallOrder = SmallOrderPublicKeys();
		List<byte[]> privateKeys = [new byte[32], Enumerable.Repeat((byte)0xFF, 32).ToArray(), RandomBytes(random), RandomBytes(random)];
		List<string> failures = [];

		foreach (byte[] privateKey in privateKeys)
		{
			using X25519 key = X25519.ImportPrivateKey(privateKey);

			foreach (byte[] peer in smallOrder)
			{
				(bool result, byte[] output) = TryDeriveSharedSecret(key, peer);

				if (result || output.AsSpan().ContainsAnyExcept(DestinationSentinel) || X25519Function(privateKey, peer).AsSpan().ContainsAnyExcept((byte)0))
				{
					failures.Add($"private key {Convert.ToHexString(privateKey)}, peer {Convert.ToHexString(peer)}");
				}
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(smallOrder.Length).IsEqualTo(14);
		}
	}

	// The check of a key that is used without a private key: [8]P on the u-line is the point at infinity just for these.
	[Test]
	public async Task SmallOrderCheckMatchesTheReference()
	{
		Random random = new(4);
		byte[][] smallOrder = SmallOrderPublicKeys();
		List<string> failures = [];
		List<byte[]> others = [EncodeInteger(2), EncodeInteger(P - 2), EncodeInteger(P + 2), EncodeInteger((BigInteger.One << 255) - 1), Nine];

		for (int i = 0; i < 4 * Iterations; ++i)
		{
			others.Add(RandomBytes(random));
		}

		foreach (byte[] publicKey in smallOrder)
		{
			if (!X25519Key.IsSmallOrder(publicKey))
			{
				failures.Add($"small order {Convert.ToHexString(publicKey)}");
			}
		}

		foreach (byte[] publicKey in others)
		{
			if (X25519Key.IsSmallOrder(publicKey) || !X25519Function(RandomBytes(random), publicKey).AsSpan().ContainsAnyExcept((byte)0))
			{
				failures.Add($"not small order {Convert.ToHexString(publicKey)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The ephemeral derivation of the hybrid KEM shares one inversion between the two results, which must be those of the separate derivations.
	[Test]
	public async Task OneInversionGivesBothEphemeralResults()
	{
		Random random = new(5);
		List<string> failures = [];

		for (int i = 0; i < 2 * Iterations; ++i)
		{
			byte[] privateKey = RandomBytes(random);
			byte[] peer = i is 0 ? Nine : RandomBytes(random);
			byte[] publicKey = new byte[X25519.PublicKeyLength];
			byte[] sharedSecret = new byte[X25519.SharedSecretLength];
			byte[] separateSecret = new byte[X25519.SharedSecretLength];
			X25519Key.DerivePublicKeyAndSharedSecret(privateKey, peer, publicKey, sharedSecret);
			bool derived = X25519Key.TryDeriveSharedSecret(privateKey, peer, separateSecret);

			if (!derived || !publicKey.AsSpan().SequenceEqual(X25519Function(privateKey, Nine)) || !sharedSecret.AsSpan().SequenceEqual(separateSecret))
			{
				failures.Add($"private key {Convert.ToHexString(privateKey)}, peer {Convert.ToHexString(peer)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task KeyOperationsDoNotAllocate()
	{
		// Without optimization, every read of a constant ReadOnlySpan<ulong>, such as a field constant, allocates a field handle.
		SkipUnlessOptimized<X25519>();

		using X25519 key = X25519.GenerateKey();
		using X25519 peer = X25519.GenerateKey();
		byte[] privateKey = new byte[X25519.PrivateKeyLength];
		byte[] publicKey = new byte[X25519.PublicKeyLength];
		byte[] peerPublicKey = ExportPublicKey(peer);
		byte[] invalidPublicKey = new byte[X25519.PublicKeyLength];
		byte[] sharedSecret = new byte[X25519.SharedSecretLength];

		bool results = Exercise(key, privateKey, publicKey, peerPublicKey, invalidPublicKey, sharedSecret);
		long before = GC.GetAllocatedBytesForCurrentThread();
		results &= Exercise(key, privateKey, publicKey, peerPublicKey, invalidPublicKey, sharedSecret);
		long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

		using (Assert.Multiple())
		{
			await Assert.That(allocated).IsZero();
			await Assert.That(results).IsTrue();
			await Assert.That(sharedSecret).IsEquivalentTo(DeriveSharedSecret(peer, publicKey), CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task DisposeErasesTheKey()
	{
		X25519 key = X25519.ImportPrivateKey(Enumerable.Repeat((byte)0xA7, 32).ToArray());
		byte[] before = KeyContents(key);
		key.Dispose();
		byte[] after = KeyContents(key);

		using (Assert.Multiple())
		{
			await Assert.That(before.AsSpan().ContainsAnyExcept((byte)0)).IsTrue();
			await Assert.That(after.AsSpan().ContainsAnyExcept((byte)0)).IsFalse();
		}
	}

	private static bool Exercise(X25519 key, byte[] privateKey, byte[] publicKey, byte[] peerPublicKey, byte[] invalidPublicKey, byte[] sharedSecret)
	{
		key.ExportPrivateKey(privateKey);
		key.ExportPublicKey(publicKey);
		bool rejected = !key.TryDeriveSharedSecret(invalidPublicKey, sharedSecret);
		return key.TryDeriveSharedSecret(peerPublicKey, sharedSecret) & rejected;
	}

	private static byte[] RandomBytes(Random random)
	{
		byte[] bytes = new byte[32];
		random.NextBytes(bytes);
		return bytes;
	}

	// The bytes of the key holder, which has no references.
	private static byte[] KeyContents(X25519 key)
	{
		object holder = typeof(X25519).GetField("_key", BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(key) ?? throw new InvalidOperationException("X25519 has no key field.");
		X25519Key copy = (X25519Key)holder;
		return MemoryMarshal.AsBytes(new ReadOnlySpan<X25519Key>(in copy)).ToArray();
	}
}
