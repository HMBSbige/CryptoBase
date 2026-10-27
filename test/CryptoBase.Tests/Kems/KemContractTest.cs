using CryptoBase.Abstractions.Kems;
using CryptoBase.Kems.Hybrid;
using CryptoBase.Kems.MLKem;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.Kems.KemTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Kems;

// Checks every IKem against the behavior its documentation promises; the known-answer and differential tests check the values.
[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
[GenerateGenericTest(typeof(MLKem512))]
[GenerateGenericTest(typeof(MLKem768))]
[GenerateGenericTest(typeof(MLKem1024))]
[GenerateGenericTest(typeof(SecP256r1MLKem768))]
[GenerateGenericTest(typeof(SecP384r1MLKem1024))]
public class KemContractTest<T> where T : class, IKem<T>
{
	[Test]
	public async Task EveryKeyFormatRoundTrips()
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
	public async Task GenerateKeyAndEncapsulateAreRandomized()
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
	public async Task ReportsWhichKeysItHolds()
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
	public async Task MissingKeysThrowInvalidOperation()
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

			foreach (byte[] input in (byte[][])[ciphertext, [], Resize(ciphertext, -1), Resize(ciphertext, 1), .. KemCiphertextChecks.Of<T>().InvalidCiphertexts])
			{
				await Assert.That(() => fromEncapsulationKey.TryDecapsulate(input, sharedSecret)).ThrowsExactly<InvalidOperationException>();
			}

			await Assert.That(seed).All(static value => value is DestinationSentinel);
			await Assert.That(decapsulationKey).All(static value => value is DestinationSentinel);
			await Assert.That(sharedSecret).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	public async Task ShortOutputsThrowAndStayUnchanged()
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

				foreach (byte[] input in (byte[][])[ciphertext, [], Resize(ciphertext, -1), Resize(ciphertext, 1), .. KemCiphertextChecks.Of<T>().InvalidCiphertexts])
				{
					await Assert.That(() => kem.TryDecapsulate(input, shortSecret)).Throws<ArgumentException>().WithParameterName("sharedSecret");
				}

				foreach (byte[] buffer in (byte[][])[seed, decapsulationKey, encapsulationKey, shortCiphertext, shortSecret, fullCiphertext, fullSecret])
				{
					await Assert.That(buffer).All(static value => value is DestinationSentinel);
				}
			}
		}
	}

	[Test]
	public async Task ImportsOfTheWrongLengthThrow()
	{
		using T kem = T.GenerateKey();
		byte[] seed = ExportPrivateSeed(kem);
		byte[] decapsulationKey = ExportDecapsulationKey(kem);
		byte[] encapsulationKey = ExportEncapsulationKey(kem);

		using (Assert.Multiple())
		{
			foreach (int delta in (int[])[-1, 1])
			{
				await Assert.That(() => T.ImportPrivateSeed(Resize(seed, delta))).Throws<ArgumentException>().WithParameterName("source");
				await Assert.That(() => T.ImportDecapsulationKey(Resize(decapsulationKey, delta))).Throws<ArgumentException>().WithParameterName("source");
				await Assert.That(() => T.ImportEncapsulationKey(Resize(encapsulationKey, delta))).Throws<ArgumentException>().WithParameterName("source");
			}

			await Assert.That(() => T.ImportPrivateSeed([])).Throws<ArgumentException>().WithParameterName("source");
			await Assert.That(() => T.ImportDecapsulationKey([])).Throws<ArgumentException>().WithParameterName("source");
			await Assert.That(() => T.ImportEncapsulationKey([])).Throws<ArgumentException>().WithParameterName("source");
		}
	}

	[Test]
	public async Task CiphertextsOfTheWrongLengthReturnFalse()
	{
		using T generated = T.GenerateKey();
		using T fromDecapsulationKey = T.ImportDecapsulationKey(ExportDecapsulationKey(generated));
		byte[] ciphertext = Encapsulate(generated).Ciphertext;

		using (Assert.Multiple())
		{
			foreach (byte[] input in (byte[][])[[], Resize(ciphertext, -1), Resize(ciphertext, 1)])
			{
				foreach (T kem in (T[])[generated, fromDecapsulationKey])
				{
					byte[] sharedSecret = CreateGuardedBuffer(0, T.SharedSecretLength);
					await Assert.That(kem.TryDecapsulate(input, sharedSecret)).IsFalse().Because($"{input.Length} bytes");
					await Assert.That(sharedSecret).All(static value => value is DestinationSentinel);
				}
			}
		}
	}

	[Test]
	public async Task OverlappingOutputsThrow()
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
	public async Task DecapsulationMayOverlapItsInput()
	{
		using T kem = T.GenerateKey();
		(byte[] ciphertext, byte[] sharedSecret) = Encapsulate(kem);

		foreach (int offset in (int[])[0, 1, T.CiphertextLength - T.SharedSecretLength, T.CiphertextLength - 1])
		{
			byte[] buffer = new byte[T.CiphertextLength + T.SharedSecretLength];
			ciphertext.CopyTo(buffer, 0);
			bool result = kem.TryDecapsulate(buffer.AsSpan(0, T.CiphertextLength), buffer.AsSpan(offset, T.SharedSecretLength));
			await Assert.That(result).IsTrue();
			await Assert.That(buffer.AsSpan(offset, T.SharedSecretLength).ToArray()).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task LongerOutputsReceiveOnlyTheirLength()
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
		bool decapsulationResult = kem.TryDecapsulate(ciphertext, decapsulatedOutput.AsSpan(1));

		using (Assert.Multiple())
		{
			await Assert.That((seedWritten, decapsulationKeyWritten, encapsulationKeyWritten)).IsEqualTo((T.PrivateSeedLength, T.DecapsulationKeyLength, T.EncapsulationKeyLength));
			await Assert.That(decapsulationResult).IsTrue();
			await AssertOutput(seedOutput, 1, seed);
			await AssertOutput(decapsulationKeyOutput, 1, decapsulationKey);
			await AssertOutput(encapsulationKeyOutput, 1, encapsulationKey);
			await AssertOutput(ciphertextOutput, 1, ciphertext);
			await AssertOutput(secretOutput, 1, sharedSecret);
			await AssertOutput(decapsulatedOutput, 1, sharedSecret);
		}
	}

	[Test]
	public async Task DisposedInstancesThrow()
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
			foreach (byte[] input in (byte[][])[ciphertext, [], .. KemCiphertextChecks.Of<T>().InvalidCiphertexts])
			{
				await Assert.That(() => kem.TryDecapsulate(input, new byte[T.SharedSecretLength])).ThrowsExactly<ObjectDisposedException>();
			}

			await Assert.That(() => kem.TryDecapsulate([], [])).ThrowsExactly<ObjectDisposedException>();
		}
	}

	// Whether tampering checked bytes changes the value depends on the algorithm, so only tampering unchecked bytes must change it.
	[Test]
	public async Task TamperedCiphertextsFailThePublicChecksOrYieldADeterministicValue()
	{
		using T generated = T.GenerateKey();
		using T fromSeed = T.ImportPrivateSeed(ExportPrivateSeed(generated));
		using T fromDecapsulationKey = T.ImportDecapsulationKey(ExportDecapsulationKey(generated));
		using T unrelated = T.GenerateKey();
		// generated twice, so that a repeated call is compared too.
		T[] holders = [generated, generated, fromSeed, fromDecapsulationKey];
		(byte[] ciphertext, byte[] sharedSecret) = Encapsulate(generated);
		KemCiphertextChecks checks = KemCiphertextChecks.Of<T>();
		List<string> failures = [];
		int index = 0;

		await Assert.That(checks.CheckedRanges).All(range => range is { Offset: >= 0, Length: > 0 } && range.Offset + range.Length <= T.CiphertextLength);

		foreach (byte[] tampered in Tampered(ciphertext))
		{
			(bool Result, byte[] Output)[] outcomes = [.. holders.Select(kem => TryDecapsulate(kem, tampered))];
			string? violation = FindViolation(outcomes, TryDecapsulate(unrelated, tampered), sharedSecret, checks.TouchesCheckedRange(ciphertext, tampered));

			if (violation is not null)
			{
				failures.Add($"tampered ciphertext {index}: {violation}");
			}

			++index;
		}

		for (int i = 0; i < checks.InvalidCiphertexts.Length; ++i)
		{
			byte[] invalid = checks.InvalidCiphertexts[i];
			(bool Result, byte[] Output)[] outcomes = [.. holders.Select(kem => TryDecapsulate(kem, invalid)), TryDecapsulate(unrelated, invalid)];

			if (invalid.Length != T.CiphertextLength || outcomes.Any(static outcome => outcome.Result || outcome.Output.AsSpan().ContainsAnyExcept(DestinationSentinel)))
			{
				failures.Add($"invalid ciphertext {i}: has the wrong length, or does not return false and leave the output unchanged");
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(index).IsEqualTo(T.CiphertextLength + 2);
			await Assert.That(failures).IsEmpty();
			await Assert.That(Decapsulate(generated, ciphertext)).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
		}
	}

	// Inputs and outputs that end where an inaccessible page begins must be read and written without faulting.
	[Test]
	public async Task StaysWithinBuffers()
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
		bool decapsulationResult = fromDecapsulationKey.TryDecapsulate(ciphertextBuffer.Span, decapsulatedBuffer.Span);
		byte[] sharedSecret = secretBuffer.Span.ToArray();
		byte[] decapsulated = decapsulatedBuffer.Span.ToArray();

		fromSeed.ExportPrivateSeed(seedBuffer.Span);
		fromSeed.ExportDecapsulationKey(decapsulationKeyBuffer.Span);
		fromSeed.ExportEncapsulationKey(encapsulationKeyBuffer.Span);

		using (Assert.Multiple())
		{
			await Assert.That(decapsulationResult).IsTrue();
			await Assert.That(decapsulated).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
			await Assert.That(seedBuffer.Span.ToArray()).IsEquivalentTo(seed, CollectionOrdering.Matching);
			await Assert.That(decapsulationKeyBuffer.Span.ToArray()).IsEquivalentTo(decapsulationKey, CollectionOrdering.Matching);
			await Assert.That(encapsulationKeyBuffer.Span.ToArray()).IsEquivalentTo(encapsulationKey, CollectionOrdering.Matching);
		}
	}

	// outcomes come from instances that hold the key the ciphertext was encapsulated to.
	private static string? FindViolation((bool Result, byte[] Output)[] outcomes, (bool Result, byte[] Output) unrelated, byte[] sharedSecret, bool touchesCheckedRange)
	{
		(bool result, byte[] output) = outcomes[0];

		if (outcomes.Any(outcome => outcome.Result != result))
		{
			return "the result differs between calls or instances";
		}

		if (unrelated.Result != result)
		{
			return "the result differs from that of an unrelated key";
		}

		if (!result)
		{
			if (unrelated.Output.AsSpan().ContainsAnyExcept(DestinationSentinel) || outcomes.Any(static outcome => outcome.Output.AsSpan().ContainsAnyExcept(DestinationSentinel)))
			{
				return "false changed the output";
			}

			return touchesCheckedRange ? null : "false, although only bytes that the checks do not read changed";
		}

		if (!output.AsSpan().ContainsAnyExcept(DestinationSentinel))
		{
			return "true left the output unchanged";
		}

		if (!touchesCheckedRange && output.AsSpan().SequenceEqual(sharedSecret))
		{
			return "the shared secret was recovered, although only bytes that the checks do not read changed";
		}

		return outcomes.All(outcome => outcome.Output.AsSpan().SequenceEqual(output)) ? null : "the value differs between calls or instances";
	}
}
