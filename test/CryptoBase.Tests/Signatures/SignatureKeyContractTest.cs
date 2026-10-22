using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.MLDsa;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Signatures;

// Checks every ISignatureKey against the behavior its documentation promises; the known-answer and differential tests check the values.
[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class SignatureKeyContractTest
{
	[Test]
	[GenerateGenericTest(typeof(MLDsa44))]
	[GenerateGenericTest(typeof(MLDsa65))]
	[GenerateGenericTest(typeof(MLDsa87))]
	public async Task EveryKeyFormatRoundTrips<T>() where T : class, ISignatureKey<T>
	{
		using T generated = GenerateKey<T>();
		byte[] subjectPublicKeyInfo = ExportSubjectPublicKeyInfo(generated);
		byte[] privateKey = ExportPkcs8PrivateKey(generated);

		using T fromPrivateKey = T.ImportPkcs8PrivateKey(privateKey);
		using T fromSubjectPublicKeyInfo = T.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);

		using (Assert.Multiple())
		{
			await Assert.That(ExportPkcs8PrivateKey(fromPrivateKey)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
			await Assert.That(ExportSubjectPublicKeyInfo(fromPrivateKey)).IsEquivalentTo(subjectPublicKeyInfo, CollectionOrdering.Matching);
			await Assert.That(ExportSubjectPublicKeyInfo(fromSubjectPublicKeyInfo)).IsEquivalentTo(subjectPublicKeyInfo, CollectionOrdering.Matching);
		}

		// Every instance verifies what every instance with the private key signs.
		byte[] message = CreateDeterministicSource(100);

		foreach (SignatureAlgorithm algorithm in AlgorithmsOf<T>())
		{
			foreach (T signer in (T[])[generated, fromPrivateKey])
			{
				byte[] signature = Sign(signer, algorithm, message);

				using (Assert.Multiple())
				{
					foreach (T verifier in (T[])[generated, fromPrivateKey, fromSubjectPublicKeyInfo])
					{
						await Assert.That(verifier.Verify(algorithm, message, signature)).IsTrue();
					}
				}
			}
		}
	}

	[Test]
	[GenerateGenericTest(typeof(MLDsa44))]
	[GenerateGenericTest(typeof(MLDsa65))]
	[GenerateGenericTest(typeof(MLDsa87))]
	public async Task ReportsWhetherItHoldsThePrivateKey<T>() where T : class, ISignatureKey<T>
	{
		using T generated = GenerateKey<T>();
		using T fromPrivateKey = T.ImportPkcs8PrivateKey(ExportPkcs8PrivateKey(generated));
		using T fromSubjectPublicKeyInfo = T.ImportSubjectPublicKeyInfo(ExportSubjectPublicKeyInfo(generated));

		using (Assert.Multiple())
		{
			await Assert.That(generated.HasPrivateKey).IsTrue();
			await Assert.That(fromPrivateKey.HasPrivateKey).IsTrue();
			await Assert.That(fromSubjectPublicKeyInfo.HasPrivateKey).IsFalse();
		}
	}

	[Test]
	[GenerateGenericTest(typeof(MLDsa44))]
	[GenerateGenericTest(typeof(MLDsa65))]
	[GenerateGenericTest(typeof(MLDsa87))]
	public async Task MissingPrivateKeyThrowsInvalidOperation<T>() where T : class, ISignatureKey<T>
	{
		using T generated = GenerateKey<T>();
		using T publicOnly = T.ImportSubjectPublicKeyInfo(ExportSubjectPublicKeyInfo(generated));
		byte[] privateKey = CreateGuardedBuffer(0, generated.Pkcs8PrivateKeyLength);

		using (Assert.Multiple())
		{
			await Assert.That(() => publicOnly.Pkcs8PrivateKeyLength).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => publicOnly.ExportPkcs8PrivateKey(privateKey)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(privateKey).All(static value => value is DestinationSentinel);

			foreach (SignatureAlgorithm algorithm in AlgorithmsOf<T>())
			{
				byte[] signature = CreateGuardedBuffer(0, publicOnly.GetMaxSignatureLength(algorithm));
				await Assert.That(() => publicOnly.Sign(algorithm, [1, 2, 3], signature)).ThrowsExactly<InvalidOperationException>();
				await Assert.That(signature).All(static value => value is DestinationSentinel);
			}
		}
	}

	[Test]
	[GenerateGenericTest(typeof(MLDsa44))]
	[GenerateGenericTest(typeof(MLDsa65))]
	[GenerateGenericTest(typeof(MLDsa87))]
	public async Task ShortOutputsThrowAndStayUnchanged<T>() where T : class, ISignatureKey<T>
	{
		using T key = GenerateKey<T>();

		foreach (int shortfall in (int[])[1, int.MaxValue])
		{
			byte[] subjectPublicKeyInfo = ShortBuffer(key.SubjectPublicKeyInfoLength, shortfall);
			byte[] privateKey = ShortBuffer(key.Pkcs8PrivateKeyLength, shortfall);

			using (Assert.Multiple())
			{
				await Assert.That(() => key.ExportSubjectPublicKeyInfo(subjectPublicKeyInfo)).Throws<ArgumentException>().WithParameterName("destination");
				await Assert.That(() => key.ExportPkcs8PrivateKey(privateKey)).Throws<ArgumentException>().WithParameterName("destination");
				await Assert.That(subjectPublicKeyInfo).All(static value => value is DestinationSentinel);
				await Assert.That(privateKey).All(static value => value is DestinationSentinel);

				foreach (SignatureAlgorithm algorithm in AlgorithmsOf<T>())
				{
					byte[] signature = ShortBuffer(key.GetMaxSignatureLength(algorithm), shortfall);
					await Assert.That(() => key.Sign(algorithm, [1, 2, 3], signature)).Throws<ArgumentException>().WithParameterName("destination");
					await Assert.That(signature).All(static value => value is DestinationSentinel);
				}
			}
		}
	}

	[Test]
	[GenerateGenericTest(typeof(MLDsa44))]
	[GenerateGenericTest(typeof(MLDsa65))]
	[GenerateGenericTest(typeof(MLDsa87))]
	public async Task LongerOutputsReceiveOnlyTheirLength<T>() where T : class, ISignatureKey<T>
	{
		using T key = GenerateKey<T>();
		byte[] subjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key);
		byte[] privateKey = ExportPkcs8PrivateKey(key);
		byte[] subjectPublicKeyInfoOutput = CreateGuardedBuffer(1, subjectPublicKeyInfo.Length);
		byte[] privateKeyOutput = CreateGuardedBuffer(1, privateKey.Length);

		int subjectPublicKeyInfoWritten = key.ExportSubjectPublicKeyInfo(subjectPublicKeyInfoOutput.AsSpan(1));
		int privateKeyWritten = key.ExportPkcs8PrivateKey(privateKeyOutput.AsSpan(1));

		using (Assert.Multiple())
		{
			await Assert.That((subjectPublicKeyInfoWritten, privateKeyWritten)).IsEqualTo((key.SubjectPublicKeyInfoLength, key.Pkcs8PrivateKeyLength));
			await AssertOutput(subjectPublicKeyInfoOutput, 1, subjectPublicKeyInfo);
			await AssertOutput(privateKeyOutput, 1, privateKey);

			foreach (SignatureAlgorithm algorithm in AlgorithmsOf<T>())
			{
				byte[] message = CreateDeterministicSource(10);
				byte[] signatureOutput = CreateGuardedBuffer(1, key.GetMaxSignatureLength(algorithm));
				int signatureWritten = key.Sign(algorithm, message, signatureOutput.AsSpan(1));
				byte[] signature = signatureOutput.AsSpan(1, signatureWritten).ToArray();

				await Assert.That(signatureWritten).IsBetween(1, key.GetMaxSignatureLength(algorithm));
				await AssertOutput(signatureOutput, 1, signature);
				await Assert.That(key.Verify(algorithm, message, signature)).IsTrue();
			}
		}
	}

	[Test]
	[GenerateGenericTest(typeof(MLDsa44))]
	[GenerateGenericTest(typeof(MLDsa65))]
	[GenerateGenericTest(typeof(MLDsa87))]
	public async Task MalformedEncodingsThrow<T>() where T : class, ISignatureKey<T>
	{
		using T key = GenerateKey<T>();
		byte[] subjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key);
		byte[] privateKey = ExportPkcs8PrivateKey(key);
		List<byte[]> otherPublicKeys = [subjectPublicKeyInfo.AsSpan(0, subjectPublicKeyInfo.Length - 1).ToArray(), [.. subjectPublicKeyInfo, 0], [0x31, .. subjectPublicKeyInfo.AsSpan(1)], [], privateKey];
		List<byte[]> otherPrivateKeys = [privateKey.AsSpan(0, privateKey.Length - 1).ToArray(), [.. privateKey, 0], [0x31, .. privateKey.AsSpan(1)], [], subjectPublicKeyInfo];

		// The keys of every other type.
		foreach (ISignatureKey other in OtherKeys<T>())
		{
			using (other)
			{
				byte[] otherSubjectPublicKeyInfo = new byte[other.SubjectPublicKeyInfoLength];
				byte[] otherPrivateKey = new byte[other.Pkcs8PrivateKeyLength];
				other.ExportSubjectPublicKeyInfo(otherSubjectPublicKeyInfo);
				other.ExportPkcs8PrivateKey(otherPrivateKey);
				otherPublicKeys.Add(otherSubjectPublicKeyInfo);
				otherPrivateKeys.Add(otherPrivateKey);
			}
		}

		using (Assert.Multiple())
		{
			foreach (byte[] encoding in otherPublicKeys)
			{
				await Assert.That(() => T.ImportSubjectPublicKeyInfo(encoding)).Throws<ArgumentException>().WithParameterName("source");
			}

			foreach (byte[] encoding in otherPrivateKeys)
			{
				await Assert.That(() => T.ImportPkcs8PrivateKey(encoding)).Throws<ArgumentException>().WithParameterName("source");
			}
		}
	}

	[Test]
	[GenerateGenericTest(typeof(MLDsa44))]
	[GenerateGenericTest(typeof(MLDsa65))]
	[GenerateGenericTest(typeof(MLDsa87))]
	public async Task SupportsOnlyItsAlgorithms<T>() where T : class, ISignatureKey<T>
	{
		using T key = GenerateKey<T>();
		SignatureAlgorithm[] supported = AlgorithmsOf<T>();
		byte[] message = CreateDeterministicSource(10);
		byte[] signature = Sign(key, supported[0], message);
		byte[] destination = CreateGuardedBuffer(0, signature.Length);

		using (Assert.Multiple())
		{
			foreach (SignatureAlgorithm algorithm in (SignatureAlgorithm[])[.. Enum.GetValues<SignatureAlgorithm>(), 0, (SignatureAlgorithm)(-1), (SignatureAlgorithm)int.MaxValue])
			{
				if (supported.Contains(algorithm))
				{
					await Assert.That(key.Supports(algorithm)).IsTrue().Because(algorithm.ToString());
					continue;
				}

				await Assert.That(key.Supports(algorithm)).IsFalse().Because(algorithm.ToString());
				await Assert.That(() => key.GetMaxSignatureLength(algorithm)).Throws<ArgumentException>().WithParameterName("algorithm");
				await Assert.That(() => key.Sign(algorithm, message, destination)).Throws<ArgumentException>().WithParameterName("algorithm");
				await Assert.That(() => key.Verify(algorithm, message, signature)).Throws<ArgumentException>().WithParameterName("algorithm");
			}

			await Assert.That(destination).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	[GenerateGenericTest(typeof(MLDsa44))]
	[GenerateGenericTest(typeof(MLDsa65))]
	[GenerateGenericTest(typeof(MLDsa87))]
	public async Task TamperedSignaturesFailVerification<T>() where T : class, ISignatureKey<T>
	{
		using T key = GenerateKey<T>();
		byte[] message = CreateDeterministicSource(40);

		foreach (SignatureAlgorithm algorithm in AlgorithmsOf<T>())
		{
			byte[] signature = Sign(key, algorithm, message);
			List<int> accepted = [];
			int index = 0;

			foreach (byte[] tampered in Tampered(signature))
			{
				if (key.Verify(algorithm, message, tampered))
				{
					accepted.Add(index);
				}

				++index;
			}

			using (Assert.Multiple())
			{
				await Assert.That(accepted).IsEmpty();
				await Assert.That(key.Verify(algorithm, message, signature)).IsTrue();
				await Assert.That(key.Verify(algorithm, Flip(message, 0), signature)).IsFalse();
				await Assert.That(key.Verify(algorithm, message, Resize(signature, -1))).IsFalse();
				await Assert.That(key.Verify(algorithm, message, Resize(signature, 1))).IsFalse();
				await Assert.That(key.Verify(algorithm, message, [])).IsFalse();
				await Assert.That(key.Verify(algorithm, message, new byte[signature.Length])).IsFalse();
			}
		}
	}

	[Test]
	[GenerateGenericTest(typeof(MLDsa44))]
	[GenerateGenericTest(typeof(MLDsa65))]
	[GenerateGenericTest(typeof(MLDsa87))]
	public async Task GenerateKeyAndSignAreRandomized<T>() where T : class, ISignatureKey<T>
	{
		using T first = GenerateKey<T>();
		using T second = GenerateKey<T>();
		byte[] message = CreateDeterministicSource(20);

		using (Assert.Multiple())
		{
			await Assert.That(ExportPkcs8PrivateKey(first)).IsNotEquivalentTo(ExportPkcs8PrivateKey(second));

			foreach (SignatureAlgorithm algorithm in AlgorithmsOf<T>())
			{
				byte[] firstSignature = Sign(first, algorithm, message);
				byte[] secondSignature = Sign(first, algorithm, message);

				await Assert.That(firstSignature).IsNotEquivalentTo(secondSignature);
				await Assert.That(first.Verify(algorithm, message, firstSignature)).IsTrue();
				await Assert.That(first.Verify(algorithm, message, secondSignature)).IsTrue();
			}
		}
	}

	[Test]
	[GenerateGenericTest(typeof(MLDsa44))]
	[GenerateGenericTest(typeof(MLDsa65))]
	[GenerateGenericTest(typeof(MLDsa87))]
	public async Task DisposedInstancesThrow<T>() where T : class, ISignatureKey<T>
	{
		T key = GenerateKey<T>();
		SignatureAlgorithm algorithm = AlgorithmsOf<T>()[0];
		byte[] message = CreateDeterministicSource(10);
		byte[] signature = Sign(key, algorithm, message);
		byte[] subjectPublicKeyInfo = new byte[key.SubjectPublicKeyInfoLength];
		byte[] privateKey = new byte[key.Pkcs8PrivateKeyLength];
		key.Dispose();
		key.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(() => key.HasPrivateKey).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.SubjectPublicKeyInfoLength).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.Pkcs8PrivateKeyLength).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.Supports(algorithm)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.GetMaxSignatureLength(algorithm)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.Sign(algorithm, message, new byte[signature.Length])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.Verify(algorithm, message, signature)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.ExportSubjectPublicKeyInfo(subjectPublicKeyInfo)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.ExportPkcs8PrivateKey(privateKey)).ThrowsExactly<ObjectDisposedException>();
		}
	}

	// Inputs and outputs that end where an inaccessible page begins must be read and written without faulting.
	[Test]
	[GenerateGenericTest(typeof(MLDsa44))]
	[GenerateGenericTest(typeof(MLDsa65))]
	[GenerateGenericTest(typeof(MLDsa87))]
	public async Task StaysWithinBuffers<T>() where T : class, ISignatureKey<T>
	{
		GuardPageBuffer.SkipUnlessSupported();

		using T generated = GenerateKey<T>();
		SignatureAlgorithm algorithm = AlgorithmsOf<T>()[0];
		byte[] subjectPublicKeyInfo = ExportSubjectPublicKeyInfo(generated);
		byte[] privateKey = ExportPkcs8PrivateKey(generated);
		byte[] message = CreateDeterministicSource(33);

		using GuardPageBuffer subjectPublicKeyInfoBuffer = new(subjectPublicKeyInfo.Length);
		using GuardPageBuffer privateKeyBuffer = new(privateKey.Length);
		using GuardPageBuffer messageBuffer = new(message.Length);
		using GuardPageBuffer signatureBuffer = new(generated.GetMaxSignatureLength(algorithm));
		subjectPublicKeyInfo.CopyTo(subjectPublicKeyInfoBuffer.Span);
		privateKey.CopyTo(privateKeyBuffer.Span);
		message.CopyTo(messageBuffer.Span);

		using T fromPrivateKey = T.ImportPkcs8PrivateKey(privateKeyBuffer.Span);
		using T fromSubjectPublicKeyInfo = T.ImportSubjectPublicKeyInfo(subjectPublicKeyInfoBuffer.Span);

		int written = fromPrivateKey.Sign(algorithm, messageBuffer.Span, signatureBuffer.Span);
		bool verified = fromSubjectPublicKeyInfo.Verify(algorithm, messageBuffer.Span, signatureBuffer.Span.Slice(0, written));
		fromPrivateKey.ExportSubjectPublicKeyInfo(subjectPublicKeyInfoBuffer.Span);
		fromPrivateKey.ExportPkcs8PrivateKey(privateKeyBuffer.Span);

		using (Assert.Multiple())
		{
			await Assert.That(written).IsEqualTo(signatureBuffer.Span.Length);
			await Assert.That(verified).IsTrue();
			await Assert.That(subjectPublicKeyInfoBuffer.Span.ToArray()).IsEquivalentTo(subjectPublicKeyInfo, CollectionOrdering.Matching);
			await Assert.That(privateKeyBuffer.Span.ToArray()).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
		}
	}

	// One key of every other ISignatureKey type.
	private static IEnumerable<ISignatureKey> OtherKeys<T>() where T : class, ISignatureKey<T>
	{
		if (typeof(T) != typeof(MLDsa44))
		{
			yield return MLDsa44.GenerateKey();
		}

		if (typeof(T) != typeof(MLDsa65))
		{
			yield return MLDsa65.GenerateKey();
		}

		if (typeof(T) != typeof(MLDsa87))
		{
			yield return MLDsa87.GenerateKey();
		}
	}
}
