using CryptoBase.Abstractions.Kems;
using CryptoBase.Kems.MLKem;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.Kems.KemTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Kems;

// Checks every IKem against the behavior its documentation promises; the known-answer and differential tests check the values.
[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class KemContractTest
{
	[Test]
	[GenerateGenericTest(typeof(MLKem512))]
	[GenerateGenericTest(typeof(MLKem768))]
	[GenerateGenericTest(typeof(MLKem1024))]
	public async Task EveryKeyFormatRoundTrips<T>() where T : class, IKem<T>
	{
		using T generated = T.GenerateKey();
		byte[] seed = ExportPrivateSeed(generated);
		byte[] decapsulationKey = ExportDecapsulationKey(generated);
		byte[] encapsulationKey = ExportEncapsulationKey(generated);

		using T fromSeed = T.ImportPrivateSeed(seed);
		using T fromDecapsulationKey = T.ImportDecapsulationKey(decapsulationKey);
		using T fromEncapsulationKey = T.ImportEncapsulationKey(encapsulationKey);

		using (Assert.Multiple())
		{
			await Assert.That(ExportPrivateSeed(fromSeed)).IsEquivalentTo(seed, CollectionOrdering.Matching);
			await Assert.That(ExportDecapsulationKey(fromSeed)).IsEquivalentTo(decapsulationKey, CollectionOrdering.Matching);
			await Assert.That(ExportEncapsulationKey(fromSeed)).IsEquivalentTo(encapsulationKey, CollectionOrdering.Matching);
			await Assert.That(ExportDecapsulationKey(fromDecapsulationKey)).IsEquivalentTo(decapsulationKey, CollectionOrdering.Matching);
			await Assert.That(ExportEncapsulationKey(fromDecapsulationKey)).IsEquivalentTo(encapsulationKey, CollectionOrdering.Matching);
			await Assert.That(ExportEncapsulationKey(fromEncapsulationKey)).IsEquivalentTo(encapsulationKey, CollectionOrdering.Matching);
		}

		// Every instance encapsulates to every instance that can decapsulate.
		T[] decapsulators = [generated, fromSeed, fromDecapsulationKey];

		foreach (T encapsulator in (T[])[.. decapsulators, fromEncapsulationKey])
		{
			(byte[] ciphertext, byte[] sharedSecret) = Encapsulate(encapsulator);

			using (Assert.Multiple())
			{
				foreach (T decapsulator in decapsulators)
				{
					await Assert.That(Decapsulate(decapsulator, ciphertext)).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
				}
			}
		}
	}

	[Test]
	[GenerateGenericTest(typeof(MLKem512))]
	[GenerateGenericTest(typeof(MLKem768))]
	[GenerateGenericTest(typeof(MLKem1024))]
	public async Task GenerateKeyAndEncapsulateAreRandomized<T>() where T : class, IKem<T>
	{
		using T first = T.GenerateKey();
		using T second = T.GenerateKey();
		(byte[] firstCiphertext, byte[] firstSecret) = Encapsulate(first);
		(byte[] secondCiphertext, byte[] secondSecret) = Encapsulate(first);

		using (Assert.Multiple())
		{
			await Assert.That(ExportPrivateSeed(first)).IsNotEquivalentTo(ExportPrivateSeed(second));
			await Assert.That(firstCiphertext).IsNotEquivalentTo(secondCiphertext);
			await Assert.That(firstSecret).IsNotEquivalentTo(secondSecret);
		}
	}

	[Test]
	[GenerateGenericTest(typeof(MLKem512))]
	[GenerateGenericTest(typeof(MLKem768))]
	[GenerateGenericTest(typeof(MLKem1024))]
	public async Task ReportsWhichKeysItHolds<T>() where T : class, IKem<T>
	{
		using T generated = T.GenerateKey();
		using T fromSeed = T.ImportPrivateSeed(ExportPrivateSeed(generated));
		using T fromDecapsulationKey = T.ImportDecapsulationKey(ExportDecapsulationKey(generated));
		using T fromEncapsulationKey = T.ImportEncapsulationKey(ExportEncapsulationKey(generated));

		using (Assert.Multiple())
		{
			await Assert.That((generated.HasPrivateSeed, generated.HasDecapsulationKey)).IsEqualTo((true, true));
			await Assert.That((fromSeed.HasPrivateSeed, fromSeed.HasDecapsulationKey)).IsEqualTo((true, true));
			await Assert.That((fromDecapsulationKey.HasPrivateSeed, fromDecapsulationKey.HasDecapsulationKey)).IsEqualTo((false, true));
			await Assert.That((fromEncapsulationKey.HasPrivateSeed, fromEncapsulationKey.HasDecapsulationKey)).IsEqualTo((false, false));
		}
	}

	[Test]
	[GenerateGenericTest(typeof(MLKem512))]
	[GenerateGenericTest(typeof(MLKem768))]
	[GenerateGenericTest(typeof(MLKem1024))]
	public async Task MissingKeysThrowInvalidOperation<T>() where T : class, IKem<T>
	{
		using T generated = T.GenerateKey();
		using T fromDecapsulationKey = T.ImportDecapsulationKey(ExportDecapsulationKey(generated));
		using T fromEncapsulationKey = T.ImportEncapsulationKey(ExportEncapsulationKey(generated));
		byte[] ciphertext = Encapsulate(generated).Ciphertext;
		byte[] seed = CreateGuardedBuffer(0, T.PrivateSeedLength);
		byte[] decapsulationKey = CreateGuardedBuffer(0, T.DecapsulationKeyLength);
		byte[] sharedSecret = CreateGuardedBuffer(0, T.SharedSecretLength);

		using (Assert.Multiple())
		{
			await Assert.That(() => fromDecapsulationKey.ExportPrivateSeed(seed)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => fromEncapsulationKey.ExportPrivateSeed(seed)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => fromEncapsulationKey.ExportDecapsulationKey(decapsulationKey)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => fromEncapsulationKey.Decapsulate(ciphertext, sharedSecret)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(seed).All(static value => value is DestinationSentinel);
			await Assert.That(decapsulationKey).All(static value => value is DestinationSentinel);
			await Assert.That(sharedSecret).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	[GenerateGenericTest(typeof(MLKem512))]
	[GenerateGenericTest(typeof(MLKem768))]
	[GenerateGenericTest(typeof(MLKem1024))]
	public async Task ShortOutputsThrowAndStayUnchanged<T>() where T : class, IKem<T>
	{
		using T kem = T.GenerateKey();
		byte[] ciphertext = Encapsulate(kem).Ciphertext;

		foreach (int shortfall in (int[])[1, int.MaxValue])
		{
			byte[] seed = ShortBuffer(T.PrivateSeedLength, shortfall);
			byte[] decapsulationKey = ShortBuffer(T.DecapsulationKeyLength, shortfall);
			byte[] encapsulationKey = ShortBuffer(T.EncapsulationKeyLength, shortfall);
			byte[] shortCiphertext = ShortBuffer(T.CiphertextLength, shortfall);
			byte[] shortSecret = ShortBuffer(T.SharedSecretLength, shortfall);
			byte[] fullCiphertext = CreateGuardedBuffer(0, T.CiphertextLength);
			byte[] fullSecret = CreateGuardedBuffer(0, T.SharedSecretLength);

			using (Assert.Multiple())
			{
				await Assert.That(() => kem.ExportPrivateSeed(seed)).Throws<ArgumentException>().WithParameterName("destination");
				await Assert.That(() => kem.ExportDecapsulationKey(decapsulationKey)).Throws<ArgumentException>().WithParameterName("destination");
				await Assert.That(() => kem.ExportEncapsulationKey(encapsulationKey)).Throws<ArgumentException>().WithParameterName("destination");
				await Assert.That(() => kem.Encapsulate(shortCiphertext, fullSecret)).Throws<ArgumentException>().WithParameterName("ciphertext");
				await Assert.That(() => kem.Encapsulate(fullCiphertext, shortSecret)).Throws<ArgumentException>().WithParameterName("sharedSecret");
				await Assert.That(() => kem.Decapsulate(ciphertext, shortSecret)).Throws<ArgumentException>().WithParameterName("sharedSecret");

				foreach (byte[] buffer in (byte[][])[seed, decapsulationKey, encapsulationKey, shortCiphertext, shortSecret, fullCiphertext, fullSecret])
				{
					await Assert.That(buffer).All(static value => value is DestinationSentinel);
				}
			}
		}
	}

	[Test]
	[GenerateGenericTest(typeof(MLKem512))]
	[GenerateGenericTest(typeof(MLKem768))]
	[GenerateGenericTest(typeof(MLKem1024))]
	public async Task InputsOfTheWrongLengthThrow<T>() where T : class, IKem<T>
	{
		using T kem = T.GenerateKey();
		byte[] seed = ExportPrivateSeed(kem);
		byte[] decapsulationKey = ExportDecapsulationKey(kem);
		byte[] encapsulationKey = ExportEncapsulationKey(kem);
		byte[] ciphertext = Encapsulate(kem).Ciphertext;
		byte[] sharedSecret = CreateGuardedBuffer(0, T.SharedSecretLength);

		using (Assert.Multiple())
		{
			foreach (int delta in (int[])[-1, 1])
			{
				await Assert.That(() => T.ImportPrivateSeed(Resize(seed, delta))).Throws<ArgumentException>().WithParameterName("source");
				await Assert.That(() => T.ImportDecapsulationKey(Resize(decapsulationKey, delta))).Throws<ArgumentException>().WithParameterName("source");
				await Assert.That(() => T.ImportEncapsulationKey(Resize(encapsulationKey, delta))).Throws<ArgumentException>().WithParameterName("source");
				await Assert.That(() => kem.Decapsulate(Resize(ciphertext, delta), sharedSecret)).Throws<ArgumentException>().WithParameterName("ciphertext");
			}

			await Assert.That(() => T.ImportPrivateSeed([])).Throws<ArgumentException>().WithParameterName("source");
			await Assert.That(() => T.ImportDecapsulationKey([])).Throws<ArgumentException>().WithParameterName("source");
			await Assert.That(() => T.ImportEncapsulationKey([])).Throws<ArgumentException>().WithParameterName("source");
			await Assert.That(() => kem.Decapsulate([], sharedSecret)).Throws<ArgumentException>().WithParameterName("ciphertext");
			await Assert.That(sharedSecret).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	[GenerateGenericTest(typeof(MLKem512))]
	[GenerateGenericTest(typeof(MLKem768))]
	[GenerateGenericTest(typeof(MLKem1024))]
	public async Task OverlappingOutputsThrow<T>() where T : class, IKem<T>
	{
		using T kem = T.GenerateKey();
		int ciphertextLength = T.CiphertextLength;
		int secretLength = T.SharedSecretLength;
		byte[] buffer = CreateGuardedBuffer(0, ciphertextLength + secretLength);

		using (Assert.Multiple())
		{
			await Assert.That(() => kem.Encapsulate(buffer.AsSpan(0, ciphertextLength), buffer.AsSpan(ciphertextLength - 1, secretLength))).Throws<ArgumentException>().WithParameterName("sharedSecret");
			await Assert.That(() => kem.Encapsulate(buffer.AsSpan(secretLength - 1, ciphertextLength), buffer.AsSpan(0, secretLength))).Throws<ArgumentException>().WithParameterName("sharedSecret");
			await Assert.That(() => kem.Encapsulate(buffer.AsSpan(0, ciphertextLength), buffer.AsSpan(0, secretLength))).Throws<ArgumentException>().WithParameterName("sharedSecret");
			await Assert.That(buffer).All(static value => value is DestinationSentinel);
		}

		// Only the bytes written count, so a secret in the unused tail of the ciphertext buffer is fine, as are adjacent outputs.
		byte[] tail = new byte[ciphertextLength + secretLength];
		kem.Encapsulate(tail, tail.AsSpan(ciphertextLength));
		byte[] adjacent = new byte[secretLength + ciphertextLength];
		kem.Encapsulate(adjacent.AsSpan(secretLength), adjacent.AsSpan(0, secretLength));

		using (Assert.Multiple())
		{
			await Assert.That(Decapsulate(kem, tail.AsSpan(0, ciphertextLength))).IsEquivalentTo(tail.AsSpan(ciphertextLength).ToArray(), CollectionOrdering.Matching);
			await Assert.That(Decapsulate(kem, adjacent.AsSpan(secretLength))).IsEquivalentTo(adjacent.AsSpan(0, secretLength).ToArray(), CollectionOrdering.Matching);
		}
	}

	[Test]
	[GenerateGenericTest(typeof(MLKem512))]
	[GenerateGenericTest(typeof(MLKem768))]
	[GenerateGenericTest(typeof(MLKem1024))]
	public async Task DecapsulationMayOverlapItsInput<T>() where T : class, IKem<T>
	{
		using T kem = T.GenerateKey();
		(byte[] ciphertext, byte[] sharedSecret) = Encapsulate(kem);

		foreach (int offset in (int[])[0, 1, T.CiphertextLength - T.SharedSecretLength, T.CiphertextLength - 1])
		{
			byte[] buffer = new byte[T.CiphertextLength + T.SharedSecretLength];
			ciphertext.CopyTo(buffer, 0);
			kem.Decapsulate(buffer.AsSpan(0, T.CiphertextLength), buffer.AsSpan(offset, T.SharedSecretLength));
			await Assert.That(buffer.AsSpan(offset, T.SharedSecretLength).ToArray()).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
		}
	}

	[Test]
	[GenerateGenericTest(typeof(MLKem512))]
	[GenerateGenericTest(typeof(MLKem768))]
	[GenerateGenericTest(typeof(MLKem1024))]
	public async Task LongerOutputsReceiveOnlyTheirLength<T>() where T : class, IKem<T>
	{
		using T kem = T.GenerateKey();
		byte[] seed = ExportPrivateSeed(kem);
		byte[] decapsulationKey = ExportDecapsulationKey(kem);
		byte[] encapsulationKey = ExportEncapsulationKey(kem);

		byte[] seedOutput = CreateGuardedBuffer(1, seed.Length);
		byte[] decapsulationKeyOutput = CreateGuardedBuffer(1, decapsulationKey.Length);
		byte[] encapsulationKeyOutput = CreateGuardedBuffer(1, encapsulationKey.Length);
		byte[] ciphertextOutput = CreateGuardedBuffer(1, T.CiphertextLength);
		byte[] secretOutput = CreateGuardedBuffer(1, T.SharedSecretLength);
		byte[] decapsulatedOutput = CreateGuardedBuffer(1, T.SharedSecretLength);

		int seedWritten = kem.ExportPrivateSeed(seedOutput.AsSpan(1));
		int decapsulationKeyWritten = kem.ExportDecapsulationKey(decapsulationKeyOutput.AsSpan(1));
		int encapsulationKeyWritten = kem.ExportEncapsulationKey(encapsulationKeyOutput.AsSpan(1));
		kem.Encapsulate(ciphertextOutput.AsSpan(1), secretOutput.AsSpan(1));
		byte[] ciphertext = ciphertextOutput.AsSpan(1, T.CiphertextLength).ToArray();
		byte[] sharedSecret = secretOutput.AsSpan(1, T.SharedSecretLength).ToArray();
		kem.Decapsulate(ciphertext, decapsulatedOutput.AsSpan(1));

		using (Assert.Multiple())
		{
			await Assert.That((seedWritten, decapsulationKeyWritten, encapsulationKeyWritten)).IsEqualTo((T.PrivateSeedLength, T.DecapsulationKeyLength, T.EncapsulationKeyLength));
			await AssertOutput(seedOutput, 1, seed);
			await AssertOutput(decapsulationKeyOutput, 1, decapsulationKey);
			await AssertOutput(encapsulationKeyOutput, 1, encapsulationKey);
			await AssertOutput(ciphertextOutput, 1, ciphertext);
			await AssertOutput(secretOutput, 1, sharedSecret);
			await AssertOutput(decapsulatedOutput, 1, sharedSecret);
		}
	}

	[Test]
	[GenerateGenericTest(typeof(MLKem512))]
	[GenerateGenericTest(typeof(MLKem768))]
	[GenerateGenericTest(typeof(MLKem1024))]
	public async Task DisposedInstancesThrow<T>() where T : class, IKem<T>
	{
		T kem = T.GenerateKey();
		byte[] ciphertext = Encapsulate(kem).Ciphertext;
		kem.Dispose();
		kem.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(() => kem.HasPrivateSeed).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => kem.HasDecapsulationKey).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => kem.ExportPrivateSeed(new byte[T.PrivateSeedLength])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => kem.ExportDecapsulationKey(new byte[T.DecapsulationKeyLength])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => kem.ExportEncapsulationKey(new byte[T.EncapsulationKeyLength])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => kem.Encapsulate(new byte[T.CiphertextLength], new byte[T.SharedSecretLength])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => kem.Decapsulate(ciphertext, new byte[T.SharedSecretLength])).ThrowsExactly<ObjectDisposedException>();
		}
	}

	// A ciphertext that was not produced for the key decapsulates to a value that differs from the shared secret, without an exception,
	// and the same value every time and from every instance with the decapsulation key.
	[Test]
	[GenerateGenericTest(typeof(MLKem512))]
	[GenerateGenericTest(typeof(MLKem768))]
	[GenerateGenericTest(typeof(MLKem1024))]
	public async Task TamperedCiphertextsAreRejectedImplicitly<T>() where T : class, IKem<T>
	{
		using T kem = T.GenerateKey();
		using T fromDecapsulationKey = T.ImportDecapsulationKey(ExportDecapsulationKey(kem));
		(byte[] ciphertext, byte[] sharedSecret) = Encapsulate(kem);
		List<string> failures = [];
		int index = 0;

		foreach (byte[] tampered in Tampered(ciphertext))
		{
			byte[] first = Decapsulate(kem, tampered);
			byte[] second = Decapsulate(kem, tampered);
			byte[] other = Decapsulate(fromDecapsulationKey, tampered);

			if (first.AsSpan().SequenceEqual(sharedSecret) || !first.AsSpan().SequenceEqual(second) || !first.AsSpan().SequenceEqual(other))
			{
				failures.Add($"tampered ciphertext {index}");
			}

			++index;
		}

		using (Assert.Multiple())
		{
			await Assert.That(index).IsEqualTo(T.CiphertextLength + 2);
			await Assert.That(failures).IsEmpty();
			await Assert.That(Decapsulate(kem, ciphertext)).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
		}
	}

	// Inputs and outputs that end where an inaccessible page begins must be read and written without faulting.
	[Test]
	[GenerateGenericTest(typeof(MLKem512))]
	[GenerateGenericTest(typeof(MLKem768))]
	[GenerateGenericTest(typeof(MLKem1024))]
	public async Task StaysWithinBuffers<T>() where T : class, IKem<T>
	{
		GuardPageBuffer.SkipUnlessSupported();

		using T generated = T.GenerateKey();
		byte[] seed = ExportPrivateSeed(generated);
		byte[] decapsulationKey = ExportDecapsulationKey(generated);
		byte[] encapsulationKey = ExportEncapsulationKey(generated);

		using GuardPageBuffer seedBuffer = new(seed.Length);
		using GuardPageBuffer decapsulationKeyBuffer = new(decapsulationKey.Length);
		using GuardPageBuffer encapsulationKeyBuffer = new(encapsulationKey.Length);
		using GuardPageBuffer ciphertextBuffer = new(T.CiphertextLength);
		using GuardPageBuffer secretBuffer = new(T.SharedSecretLength);
		using GuardPageBuffer decapsulatedBuffer = new(T.SharedSecretLength);
		seed.CopyTo(seedBuffer.Span);
		decapsulationKey.CopyTo(decapsulationKeyBuffer.Span);
		encapsulationKey.CopyTo(encapsulationKeyBuffer.Span);

		using T fromSeed = T.ImportPrivateSeed(seedBuffer.Span);
		using T fromDecapsulationKey = T.ImportDecapsulationKey(decapsulationKeyBuffer.Span);
		using T fromEncapsulationKey = T.ImportEncapsulationKey(encapsulationKeyBuffer.Span);

		fromEncapsulationKey.Encapsulate(ciphertextBuffer.Span, secretBuffer.Span);
		fromDecapsulationKey.Decapsulate(ciphertextBuffer.Span, decapsulatedBuffer.Span);
		byte[] sharedSecret = secretBuffer.Span.ToArray();
		byte[] decapsulated = decapsulatedBuffer.Span.ToArray();

		fromSeed.ExportPrivateSeed(seedBuffer.Span);
		fromSeed.ExportDecapsulationKey(decapsulationKeyBuffer.Span);
		fromSeed.ExportEncapsulationKey(encapsulationKeyBuffer.Span);

		using (Assert.Multiple())
		{
			await Assert.That(decapsulated).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
			await Assert.That(seedBuffer.Span.ToArray()).IsEquivalentTo(seed, CollectionOrdering.Matching);
			await Assert.That(decapsulationKeyBuffer.Span.ToArray()).IsEquivalentTo(decapsulationKey, CollectionOrdering.Matching);
			await Assert.That(encapsulationKeyBuffer.Span.ToArray()).IsEquivalentTo(encapsulationKey, CollectionOrdering.Matching);
		}
	}
}
