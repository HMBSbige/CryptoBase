using CryptoBase.Hashes.Sha1;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Rsa;
using static CryptoBase.Tests.Rsa.RsaTestUtils;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.Rsa;

internal class RsaOaepTest
{
	// k − 2hLen − 2 bytes (RFC 8017, Sec. 7.1.1): the shortest modulus, of 64 bytes, leaves 6 with SHA-224 and is too short for SHA-256.
	[Test]
	public async Task MaxPlaintextLengthFollowsRfc8017()
	{
		using RsaKey key = ImportKey();
		using RsaKey shortest = ImportKey(512);

		using (Assert.Multiple())
		{
			await Assert.That(key.ModulusLength).IsEqualTo(256);
			await Assert.That(key.GetMaxOaepPlaintextLength<Sha1Core>()).IsEqualTo(214);
			await Assert.That(key.GetMaxOaepPlaintextLength<Sha256Core>()).IsEqualTo(190);
			await Assert.That(key.GetMaxOaepPlaintextLength<Sha512Core>()).IsEqualTo(126);
			await Assert.That(shortest.ModulusLength).IsEqualTo(64);
			await Assert.That(shortest.GetMaxOaepPlaintextLength<Sha224Core>()).IsEqualTo(6);
			await Assert.That(() => shortest.GetMaxOaepPlaintextLength<Sha256Core>()).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => shortest.EncryptOaep<Sha256Core>([], new byte[64])).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => shortest.TryDecryptOaep<Sha256Core>(new byte[64], new byte[64], out _)).ThrowsExactly<NotSupportedException>();
		}
	}

	[Test]
	public async Task EncryptionsOfOnePlaintextDiffer()
	{
		using RsaKey key = ImportKey();
		byte[] first = new byte[key.ModulusLength];
		byte[] second = new byte[key.ModulusLength];
		key.EncryptOaep<Sha256Core>([1, 2, 3], first);
		key.EncryptOaep<Sha256Core>([1, 2, 3], second);

		await Assert.That(first).IsNotEquivalentTo(second);
	}

	// One failure in the decoding, from MGF1 with another hash, and one before it, from the modulus, the least value that is not reduced.
	// The last decryption shows that the first ciphertext fails only for the hash of MGF1.
	[Test]
	public async Task FailedDecryptionWritesNothing()
	{
		using RsaKey key = ImportKey();
		byte[] ciphertext = new byte[key.ModulusLength];
		key.EncryptOaep<Sha256Core, Sha1Core>([1, 2, 3], ciphertext);
		byte[] modulus = PrivateParameters().Modulus ?? throw new InvalidOperationException("The key has no modulus.");
		byte[] destination = CreateGuardedBuffer(0, key.ModulusLength);

		using (Assert.Multiple())
		{
			await Assert.That(key.TryDecryptOaep<Sha256Core>(ciphertext, destination, out int bytesWritten)).IsFalse();
			await Assert.That(bytesWritten).IsZero();
			await Assert.That(key.TryDecryptOaep<Sha256Core>(modulus, destination, out bytesWritten)).IsFalse();
			await Assert.That(bytesWritten).IsZero();
			await Assert.That(destination).All(static value => value is DestinationSentinel);
			await Assert.That(key.TryDecryptOaep<Sha256Core, Sha1Core>(ciphertext, destination, out bytesWritten)).IsTrue();
			await Assert.That(bytesWritten).IsEqualTo(3);
		}
	}

	// Decryption needs room for the longest plaintext, so a destination of maxLength − 1 bytes throws although the plaintext has 1 byte.
	[Test]
	public async Task UnusableArgumentsAndKeysThrow()
	{
		using RsaKey key = ImportKey();
		using RsaKey publicKey = RsaKey.ImportSubjectPublicKeyInfo(ExportSubjectPublicKeyInfo(key));
		using RsaKey pssPublicKey = RsaKey.ImportSubjectPublicKeyInfo(SubjectPublicKeyInfo(RsassaPssIdentifier(withParameters: false), ExportRsaPublicKey(key)));
		using RsaKey pssPrivateKey = RsaKey.ImportPkcs8PrivateKey(PrivateKeyInfo(RsassaPssIdentifier(withParameters: false), ExportRsaPrivateKey(key)));
		int maxLength = key.GetMaxOaepPlaintextLength<Sha256Core>();
		byte[] ciphertext = new byte[key.ModulusLength];
		key.EncryptOaep<Sha256Core>([1], ciphertext);
		byte[] destination = CreateGuardedBuffer(0, key.ModulusLength);

		using (Assert.Multiple())
		{
			await Assert.That(() => key.EncryptOaep<Sha256Core>(new byte[maxLength + 1], destination)).Throws<ArgumentException>().WithParameterName("plaintext");
			await Assert.That(() => key.EncryptOaep<Sha256Core>([1], destination.AsSpan(0, key.ModulusLength - 1))).Throws<ArgumentException>().WithParameterName("destination");
			await Assert.That(() => key.TryDecryptOaep<Sha256Core>(ciphertext, destination.AsSpan(0, maxLength - 1), out _)).Throws<ArgumentException>().WithParameterName("destination");
			await Assert.That(destination).All(static value => value is DestinationSentinel);
			await Assert.That(() => publicKey.TryDecryptOaep<Sha256Core>(ciphertext, destination, out _)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => pssPublicKey.GetMaxOaepPlaintextLength<Sha256Core>()).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => pssPublicKey.EncryptOaep<Sha256Core>([1], destination)).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => pssPrivateKey.TryDecryptOaep<Sha256Core>(ciphertext, destination, out _)).ThrowsExactly<NotSupportedException>();
		}
	}

	[Test]
	public async Task BuffersMayOverlap()
	{
		using RsaKey key = ImportKey();
		byte[] plaintext = CreateDeterministicSource(key.GetMaxOaepPlaintextLength<Sha256Core>());
		byte[] buffer = new byte[key.ModulusLength];
		plaintext.CopyTo(buffer, 0);

		key.EncryptOaep<Sha256Core>(buffer.AsSpan(0, plaintext.Length), buffer);
		bool decrypts = key.TryDecryptOaep<Sha256Core>(buffer, buffer, out int length);

		using (Assert.Multiple())
		{
			await Assert.That(decrypts).IsTrue();
			await Assert.That(buffer.AsSpan(0, length).ToArray()).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task EncryptsAndDecryptsConcurrently()
	{
		using RsaKey key = ImportKey();
		int failures = 0;

		Parallel.For(0, 4 * Math.Max(4, Environment.ProcessorCount), i =>
		{
			byte[] plaintext = CreateDeterministicSource(i % 64);
			byte[] ciphertext = new byte[key.ModulusLength];
			byte[] decrypted = new byte[key.GetMaxOaepPlaintextLength<Sha256Core>()];
			key.EncryptOaep<Sha256Core>(plaintext, ciphertext);

			if (!key.TryDecryptOaep<Sha256Core>(ciphertext, decrypted, out int length) || !decrypted.AsSpan(0, length).SequenceEqual(plaintext))
			{
				Interlocked.Increment(ref failures);
			}
		});

		await Assert.That(failures).IsZero();
	}

	[Test]
	public async Task DisposedInstancesThrow()
	{
		RsaKey key = ImportKey();
		byte[] buffer = new byte[key.ModulusLength];
		key.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(() => key.ModulusLength).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.GetMaxOaepPlaintextLength<Sha256Core>()).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.EncryptOaep<Sha256Core>([], buffer)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.TryDecryptOaep<Sha256Core>(buffer, buffer, out _)).ThrowsExactly<ObjectDisposedException>();
		}
	}
}
