using CryptoBase.Abstractions.KeyAgreements;
using CryptoBase.KeyAgreements.Ecdh;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.KeyAgreements.KeyAgreementTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.KeyAgreements;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class KeyAgreementContractTest
{
	[Test]
	[GenerateGenericTest(typeof(EcdhP256))]
	[GenerateGenericTest(typeof(EcdhP384))]
	[GenerateGenericTest(typeof(EcdhP521))]
	public async Task PrivateKeysRoundTrip<T>() where T : class, IKeyAgreement<T>
	{
		using T generated = T.GenerateKey();
		byte[] privateKey = ExportPrivateKey(generated);
		byte[] publicKey = ExportPublicKey(generated);

		using T imported = T.ImportPrivateKey(privateKey);

		using (Assert.Multiple())
		{
			await Assert.That(ExportPrivateKey(imported)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
			await Assert.That(ExportPublicKey(imported)).IsEquivalentTo(publicKey, CollectionOrdering.Matching);
		}
	}

	[Test]
	[GenerateGenericTest(typeof(EcdhP256))]
	[GenerateGenericTest(typeof(EcdhP384))]
	[GenerateGenericTest(typeof(EcdhP521))]
	public async Task BothPartiesDeriveTheSameSecret<T>() where T : class, IKeyAgreement<T>
	{
		using T alice = T.GenerateKey();
		using T bob = T.GenerateKey();
		using T aliceCopy = T.ImportPrivateKey(ExportPrivateKey(alice));
		byte[] sharedSecret = DeriveSharedSecret(alice, ExportPublicKey(bob));

		using (Assert.Multiple())
		{
			await Assert.That(sharedSecret).Contains(static value => value is not DestinationSentinel);
			await Assert.That(DeriveSharedSecret(bob, ExportPublicKey(alice))).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
			await Assert.That(DeriveSharedSecret(bob, ExportPublicKey(aliceCopy))).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
			await Assert.That(DeriveSharedSecret(aliceCopy, ExportPublicKey(bob))).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
			await Assert.That(DeriveSharedSecret(alice, ExportPublicKey(bob))).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
		}
	}

	[Test]
	[GenerateGenericTest(typeof(EcdhP256))]
	[GenerateGenericTest(typeof(EcdhP384))]
	[GenerateGenericTest(typeof(EcdhP521))]
	public async Task UnrelatedKeysGiveOtherSecrets<T>() where T : class, IKeyAgreement<T>
	{
		using T alice = T.GenerateKey();
		using T bob = T.GenerateKey();
		using T carol = T.GenerateKey();
		byte[] sharedSecret = DeriveSharedSecret(alice, ExportPublicKey(bob));

		using (Assert.Multiple())
		{
			await Assert.That(DeriveSharedSecret(alice, ExportPublicKey(carol))).IsNotEquivalentTo(sharedSecret);
			await Assert.That(DeriveSharedSecret(carol, ExportPublicKey(bob))).IsNotEquivalentTo(sharedSecret);
		}
	}

	[Test]
	[GenerateGenericTest(typeof(EcdhP256))]
	[GenerateGenericTest(typeof(EcdhP384))]
	[GenerateGenericTest(typeof(EcdhP521))]
	public async Task GenerateKeyIsRandomized<T>() where T : class, IKeyAgreement<T>
	{
		using T first = T.GenerateKey();
		using T second = T.GenerateKey();

		using (Assert.Multiple())
		{
			await Assert.That(ExportPrivateKey(first)).IsNotEquivalentTo(ExportPrivateKey(second));
			await Assert.That(ExportPublicKey(first)).IsNotEquivalentTo(ExportPublicKey(second));
		}
	}

	[Test]
	[GenerateGenericTest(typeof(EcdhP256))]
	[GenerateGenericTest(typeof(EcdhP384))]
	[GenerateGenericTest(typeof(EcdhP521))]
	public async Task PublicKeysOfTheWrongLengthReturnFalse<T>() where T : class, IKeyAgreement<T>
	{
		using T key = T.GenerateKey();
		using T peer = T.GenerateKey();
		byte[] publicKey = ExportPublicKey(peer);

		using (Assert.Multiple())
		{
			foreach (byte[] input in (byte[][])[[], Resize(publicKey, -1), Resize(publicKey, 1), [.. publicKey, .. publicKey]])
			{
				(bool result, byte[] output) = TryDeriveSharedSecret(key, input);
				await Assert.That(result).IsFalse().Because($"{input.Length} bytes");
				await Assert.That(output).All(static value => value is DestinationSentinel);
			}
		}
	}

	[Test]
	[GenerateGenericTest(typeof(EcdhP256))]
	[GenerateGenericTest(typeof(EcdhP384))]
	[GenerateGenericTest(typeof(EcdhP521))]
	public async Task InvalidPublicKeysReturnFalse<T>() where T : class, IKeyAgreement<T>
	{
		using T first = T.GenerateKey();
		using T second = T.GenerateKey();
		byte[][] invalidPublicKeys = KeyAgreementChecks.Of<T>().InvalidPublicKeys;
		List<string> failures = [];

		for (int i = 0; i < invalidPublicKeys.Length; ++i)
		{
			byte[] invalid = invalidPublicKeys[i];

			if (invalid.Length != T.PublicKeyLength)
			{
				failures.Add($"invalid public key {i}: has the wrong length");
				continue;
			}

			foreach (T key in (T[])[first, second])
			{
				(bool result, byte[] output) = TryDeriveSharedSecret(key, invalid);

				if (result || output.AsSpan().ContainsAnyExcept(DestinationSentinel))
				{
					failures.Add($"invalid public key {i}: does not return false and leave the output unchanged");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[GenerateGenericTest(typeof(EcdhP256))]
	[GenerateGenericTest(typeof(EcdhP384))]
	[GenerateGenericTest(typeof(EcdhP521))]
	public async Task InvalidPrivateKeysThrow<T>() where T : class, IKeyAgreement<T>
	{
		byte[][] invalidPrivateKeys = KeyAgreementChecks.Of<T>().InvalidPrivateKeys;

		using (Assert.Multiple())
		{
			for (int i = 0; i < invalidPrivateKeys.Length; ++i)
			{
				byte[] invalid = invalidPrivateKeys[i];
				await Assert.That(invalid.Length).IsEqualTo(T.PrivateKeyLength).Because($"invalid private key {i}");
				await Assert.That(() => T.ImportPrivateKey(invalid)).Throws<ArgumentException>().WithParameterName("source").Because($"invalid private key {i}");
			}
		}
	}

	[Test]
	[GenerateGenericTest(typeof(EcdhP256))]
	[GenerateGenericTest(typeof(EcdhP384))]
	[GenerateGenericTest(typeof(EcdhP521))]
	public async Task ImportsOfTheWrongLengthThrow<T>() where T : class, IKeyAgreement<T>
	{
		using T key = T.GenerateKey();
		byte[] privateKey = ExportPrivateKey(key);

		using (Assert.Multiple())
		{
			foreach (byte[] input in (byte[][])[[], Resize(privateKey, -1), Resize(privateKey, 1)])
			{
				await Assert.That(() => T.ImportPrivateKey(input)).Throws<ArgumentException>().WithParameterName("source").Because($"{input.Length} bytes");
			}
		}
	}

	[Test]
	[GenerateGenericTest(typeof(EcdhP256))]
	[GenerateGenericTest(typeof(EcdhP384))]
	[GenerateGenericTest(typeof(EcdhP521))]
	public async Task ShortOutputsThrowAndStayUnchanged<T>() where T : class, IKeyAgreement<T>
	{
		using T key = T.GenerateKey();
		using T peer = T.GenerateKey();
		byte[][] peerPublicKeys = PeerPublicKeys<T>(ExportPublicKey(peer));

		foreach (int shortfall in (int[])[1, int.MaxValue])
		{
			byte[] privateKey = ShortBuffer(T.PrivateKeyLength, shortfall);
			byte[] publicKey = ShortBuffer(T.PublicKeyLength, shortfall);
			byte[] sharedSecret = ShortBuffer(T.SharedSecretLength, shortfall);

			using (Assert.Multiple())
			{
				await Assert.That(() => key.ExportPrivateKey(privateKey)).Throws<ArgumentException>().WithParameterName("destination");
				await Assert.That(() => key.ExportPublicKey(publicKey)).Throws<ArgumentException>().WithParameterName("destination");

				foreach (byte[] input in peerPublicKeys)
				{
					await Assert.That(() => key.TryDeriveSharedSecret(input, sharedSecret)).Throws<ArgumentException>().WithParameterName("sharedSecret");
				}

				foreach (byte[] buffer in (byte[][])[privateKey, publicKey, sharedSecret])
				{
					await Assert.That(buffer).All(static value => value is DestinationSentinel);
				}
			}
		}
	}

	[Test]
	[GenerateGenericTest(typeof(EcdhP256))]
	[GenerateGenericTest(typeof(EcdhP384))]
	[GenerateGenericTest(typeof(EcdhP521))]
	public async Task LongerOutputsReceiveOnlyTheirLength<T>() where T : class, IKeyAgreement<T>
	{
		using T key = T.GenerateKey();
		using T peer = T.GenerateKey();
		byte[] privateKey = ExportPrivateKey(key);
		byte[] publicKey = ExportPublicKey(key);
		byte[] peerPublicKey = ExportPublicKey(peer);
		byte[] sharedSecret = DeriveSharedSecret(peer, publicKey);

		byte[] privateKeyOutput = CreateGuardedBuffer(1, privateKey.Length);
		byte[] publicKeyOutput = CreateGuardedBuffer(1, publicKey.Length);
		byte[] sharedSecretOutput = CreateGuardedBuffer(1, sharedSecret.Length);

		int privateKeyWritten = key.ExportPrivateKey(privateKeyOutput.AsSpan(1));
		int publicKeyWritten = key.ExportPublicKey(publicKeyOutput.AsSpan(1));
		bool derivationResult = key.TryDeriveSharedSecret(peerPublicKey, sharedSecretOutput.AsSpan(1));

		using (Assert.Multiple())
		{
			await Assert.That((privateKeyWritten, publicKeyWritten)).IsEqualTo((T.PrivateKeyLength, T.PublicKeyLength));
			await Assert.That(sharedSecret.Length).IsEqualTo(T.SharedSecretLength);
			await Assert.That(derivationResult).IsTrue();
			await AssertOutput(privateKeyOutput, 1, privateKey);
			await AssertOutput(publicKeyOutput, 1, publicKey);
			await AssertOutput(sharedSecretOutput, 1, sharedSecret);
		}
	}

	[Test]
	[GenerateGenericTest(typeof(EcdhP256))]
	[GenerateGenericTest(typeof(EcdhP384))]
	[GenerateGenericTest(typeof(EcdhP521))]
	public async Task DerivationMayOverlapItsInput<T>() where T : class, IKeyAgreement<T>
	{
		using T key = T.GenerateKey();
		using T peer = T.GenerateKey();
		byte[] peerPublicKey = ExportPublicKey(peer);
		byte[] sharedSecret = DeriveSharedSecret(key, peerPublicKey);
		int publicKeyLength = T.PublicKeyLength;
		int secretLength = T.SharedSecretLength;

		using (Assert.Multiple())
		{
			foreach ((int keyOffset, int secretOffset) in ((int, int)[])[(0, 0), (0, 1), (0, publicKeyLength - secretLength), (0, publicKeyLength - 1), (1, 0), (secretLength - 1, 0)])
			{
				byte[] buffer = new byte[publicKeyLength + secretLength];
				peerPublicKey.CopyTo(buffer, keyOffset);
				bool result = key.TryDeriveSharedSecret(buffer.AsSpan(keyOffset, publicKeyLength), buffer.AsSpan(secretOffset, secretLength));
				await Assert.That(result).IsTrue().Because($"key at {keyOffset}, secret at {secretOffset}");
				await Assert.That(buffer.AsSpan(secretOffset, secretLength).ToArray()).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching).Because($"key at {keyOffset}, secret at {secretOffset}");
			}
		}
	}

	[Test]
	[GenerateGenericTest(typeof(EcdhP256))]
	[GenerateGenericTest(typeof(EcdhP384))]
	[GenerateGenericTest(typeof(EcdhP521))]
	public async Task DisposedInstancesThrow<T>() where T : class, IKeyAgreement<T>
	{
		T key = T.GenerateKey();
		using T peer = T.GenerateKey();
		byte[][] peerPublicKeys = PeerPublicKeys<T>(ExportPublicKey(peer));
		key.Dispose();
		key.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(() => key.ExportPrivateKey(new byte[T.PrivateKeyLength])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.ExportPublicKey(new byte[T.PublicKeyLength])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.TryDeriveSharedSecret(peerPublicKeys[0], [])).ThrowsExactly<ObjectDisposedException>();

			foreach (byte[] input in peerPublicKeys)
			{
				await Assert.That(() => key.TryDeriveSharedSecret(input, new byte[T.SharedSecretLength])).ThrowsExactly<ObjectDisposedException>();
			}
		}
	}

	[Test]
	[GenerateGenericTest(typeof(EcdhP256))]
	[GenerateGenericTest(typeof(EcdhP384))]
	[GenerateGenericTest(typeof(EcdhP521))]
	public async Task StaysWithinBuffers<T>() where T : class, IKeyAgreement<T>
	{
		GuardPageBuffer.SkipUnlessSupported();

		using T generated = T.GenerateKey();
		using T peer = T.GenerateKey();
		byte[] privateKey = ExportPrivateKey(generated);
		byte[] publicKey = ExportPublicKey(generated);
		byte[] sharedSecret = DeriveSharedSecret(peer, publicKey);

		using GuardPageBuffer privateKeyBuffer = new(privateKey.Length);
		using GuardPageBuffer publicKeyBuffer = new(publicKey.Length);
		using GuardPageBuffer peerPublicKeyBuffer = new(T.PublicKeyLength);
		using GuardPageBuffer sharedSecretBuffer = new(T.SharedSecretLength);
		privateKey.CopyTo(privateKeyBuffer.Span);
		peer.ExportPublicKey(peerPublicKeyBuffer.Span);

		using T imported = T.ImportPrivateKey(privateKeyBuffer.Span);
		imported.ExportPrivateKey(privateKeyBuffer.Span);
		imported.ExportPublicKey(publicKeyBuffer.Span);
		bool derivationResult = imported.TryDeriveSharedSecret(peerPublicKeyBuffer.Span, sharedSecretBuffer.Span);

		using (Assert.Multiple())
		{
			await Assert.That(derivationResult).IsTrue();
			await Assert.That(sharedSecretBuffer.Span.ToArray()).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
			await Assert.That(privateKeyBuffer.Span.ToArray()).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
			await Assert.That(publicKeyBuffer.Span.ToArray()).IsEquivalentTo(publicKey, CollectionOrdering.Matching);
		}
	}

	private static byte[][] PeerPublicKeys<T>(byte[] valid) where T : class, IKeyAgreement<T>
	{
		return [valid, [], Resize(valid, -1), Resize(valid, 1), .. KeyAgreementChecks.Of<T>().InvalidPublicKeys];
	}
}
