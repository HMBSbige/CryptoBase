using CryptoBase.Hpke;
using CryptoBase.Tests.Kems;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using static CryptoBase.Tests.Hpke.HpkeTestUtils;
using static CryptoBase.Tests.Kems.KemTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hpke;

// The contexts through the public API, with every KEM. HpkeVectorTest checks the values.
[GenerateGenericTest(typeof(DhKemP256))]
[GenerateGenericTest(typeof(DhKemP384))]
[GenerateGenericTest(typeof(DhKemP521))]
[GenerateGenericTest(typeof(DhKemX25519))]
[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before the keys and contexts are disposed.")]
public class HpkeContextTest<TKem> where TKem : class, IHpkeAuthKem<TKem>
{
	// ReSharper disable once StaticMemberInGenericType
	private static readonly byte[] Info = "HPKE context test"u8.ToArray();
	// ReSharper disable once StaticMemberInGenericType
	private static readonly byte[] Psk = CreateDeterministicSource(32);
	// ReSharper disable once StaticMemberInGenericType
	private static readonly byte[] PskId = "PSK ID"u8.ToArray();

	[Test]
	[MatrixDataSource]
	public async Task MessagesOpenInOrderAndExportsAgree([Matrix] HpkeTestMode mode, [Matrix] HpkeKdf kdf, [Matrix(HpkeAead.Aes128Gcm, HpkeAead.Aes256Gcm, HpkeAead.ChaCha20Poly1305)] HpkeAead aead)
	{
		using Session session = new(mode, kdf, aead);
		byte[][] messages = [[], CreateDeterministicSource(1), CreateDeterministicSource(100), CreateDeterministicSource(1000)];
		int maxExportLength = 255 * kdf.HashLength;

		using (Assert.Multiple())
		{
			await Assert.That((session.Sender.Kdf, session.Sender.Aead, session.Recipient.Kdf, session.Recipient.Aead)).IsEqualTo((kdf, aead, kdf, aead));

			for (int i = 0; i < messages.Length; ++i)
			{
				byte[] associatedData = [(byte)i];
				byte[] ciphertext = Seal(session.Sender, messages[i], associatedData);
				await Assert.That(ciphertext.Length).IsEqualTo(messages[i].Length + aead.TagSize);
				await Assert.That(Open(session.Recipient, ciphertext, associatedData)).IsEquivalentTo(messages[i], CollectionOrdering.Matching);
			}

			await Assert.That((session.Sender.SequenceNumber, session.Recipient.SequenceNumber)).IsEqualTo(((ulong)messages.Length, (ulong)messages.Length));

			foreach (int length in (int[])[1, kdf.HashLength, kdf.HashLength + 1, maxExportLength])
			{
				await Assert.That(Export(session.Sender, Info, length)).IsEquivalentTo(Export(session.Recipient, Info, length), CollectionOrdering.Matching);
			}

			await Assert.That(Export(session.Sender, [], 32)).IsNotEquivalentTo(Export(session.Sender, [0], 32));
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task ExportOnlyContextsOnlyExport([Matrix] HpkeTestMode mode)
	{
		using Session session = new(mode, HpkeKdf.HkdfSha384, HpkeAead.ExportOnly);
		byte[] ciphertext = CreateGuardedBuffer(0, 32);
		byte[] plaintext = CreateGuardedBuffer(0, 32);

		using (Assert.Multiple())
		{
			await Assert.That(() => session.Sender.Seal([], ciphertext)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => session.Recipient.TryOpen(ciphertext, plaintext)).ThrowsExactly<InvalidOperationException>();
			await Assert.That((session.Sender.SequenceNumber, session.Recipient.SequenceNumber)).IsEqualTo((0UL, 0UL));
			await Assert.That(ciphertext).All(static value => value is DestinationSentinel);
			await Assert.That(plaintext).All(static value => value is DestinationSentinel);
			await Assert.That(Export(session.Sender, Info, 100)).IsEquivalentTo(Export(session.Recipient, Info, 100), CollectionOrdering.Matching);
		}
	}

	// A recipient set up again from the same encapsulated key goes on at sequence number 1.
	[Test]
	public async Task RecipientsSetUpAgainResumeAtTheirSequenceNumber()
	{
		using Session session = new(HpkeTestMode.Base, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm);
		byte[][] messages = [CreateDeterministicSource(10), CreateDeterministicSource(20), CreateDeterministicSource(30)];
		byte[][] ciphertexts = [.. messages.Select(message => Seal(session.Sender, message, Info))];
		byte[]? opened = Open(session.Recipient, ciphertexts[0], Info);
		using HpkeRecipientContext resumed = session.SetUpRecipientAgain();

		using (Assert.Multiple())
		{
			await Assert.That(opened).IsEquivalentTo(messages[0], CollectionOrdering.Matching);
			await Assert.That(Open(resumed, ciphertexts[1], Info)).IsNull();
			await Assert.That(resumed.SequenceNumber).IsEqualTo(0UL);

			resumed.SequenceNumber = 1;
			await Assert.That(Open(resumed, ciphertexts[1], Info)).IsEquivalentTo(messages[1], CollectionOrdering.Matching);
			await Assert.That(Open(resumed, ciphertexts[2], Info)).IsEquivalentTo(messages[2], CollectionOrdering.Matching);
			await Assert.That(resumed.SequenceNumber).IsEqualTo(3UL);
			await Assert.That(Export(resumed, Info, 32)).IsEquivalentTo(Export(session.Recipient, Info, 32), CollectionOrdering.Matching);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task TamperedMessagesFailAndKeepTheSequenceNumber([Matrix(HpkeAead.Aes128Gcm, HpkeAead.Aes256Gcm, HpkeAead.ChaCha20Poly1305)] HpkeAead aead)
	{
		using Session session = new(HpkeTestMode.Base, HpkeKdf.HkdfSha256, aead);
		byte[] message = CreateDeterministicSource(40);
		byte[] associatedData = "header"u8.ToArray();
		byte[] ciphertext = Seal(session.Sender, message, associatedData);
		(byte[] Ciphertext, byte[] AssociatedData, string Change)[] tampered =
		[
			(Flip(ciphertext, 0), associatedData, "first byte"),
			(Flip(ciphertext, message.Length - 1), associatedData, "last byte of the message"),
			(Flip(ciphertext, message.Length), associatedData, "first byte of the tag"),
			(Flip(ciphertext, ciphertext.Length - 1), associatedData, "last byte of the tag"),
			(ciphertext, Flip(associatedData, 0), "associated data"),
			(ciphertext, [], "no associated data"),
			(Resize(ciphertext, -1), associatedData, "one byte less"),
			(Resize(ciphertext, 1), associatedData, "one byte more"),
			(ciphertext.AsSpan(0, aead.TagSize).ToArray(), associatedData, "tag length"),
			(ciphertext.AsSpan(0, aead.TagSize - 1).ToArray(), associatedData, "shorter than the tag"),
			([], associatedData, "empty")
		];

		using (Assert.Multiple())
		{
			foreach ((byte[] input, byte[] inputAssociatedData, string change) in tampered)
			{
				int length = Math.Max(0, input.Length - aead.TagSize);
				byte[] plaintext = CreateGuardedBuffer(0, length);
				bool opened = session.Recipient.TryOpen(input, plaintext, inputAssociatedData);

				await Assert.That(opened).IsFalse().Because(change);
				await Assert.That(session.Recipient.SequenceNumber).IsEqualTo(0UL).Because(change);
				// The part that would have received the message is cleared, and the rest is left alone.
				await Assert.That(plaintext.AsSpan(0, length).ContainsAnyExcept((byte)0)).IsFalse().Because(change);
				await Assert.That(plaintext.AsSpan(length).ToArray()).All(static value => value is DestinationSentinel).Because(change);
			}

			await Assert.That(Open(session.Recipient, ciphertext, associatedData)).IsEquivalentTo(message, CollectionOrdering.Matching);
			await Assert.That(session.Recipient.SequenceNumber).IsEqualTo(1UL);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task OtherInputsSetUpContextsThatOpenNothing([Matrix] HpkeTestMode mode)
	{
		using Session session = new(mode, HpkeKdf.HkdfSha256, HpkeAead.ChaCha20Poly1305);
		using TKem otherRecipient = TKem.GenerateKey();
		using TKem otherSender = TKem.GenerateKey();
		byte[] ciphertext = Seal(session.Sender, CreateDeterministicSource(16), []);
		byte[] otherPsk = Flip(Psk, 0);
		List<(HpkeRecipientContext? Context, string Change)> others =
		[
			(TryCreateRecipient(mode, session.RecipientKey, session.SenderPublicKey, HpkeKdf.HkdfSha256, HpkeAead.ChaCha20Poly1305, session.Enc, [.. Info, 0], Psk, PskId), "info"),
			(TryCreateRecipient(mode, otherRecipient, session.SenderPublicKey, HpkeKdf.HkdfSha256, HpkeAead.ChaCha20Poly1305, session.Enc, Info, Psk, PskId), "recipient"),
			(TryCreateRecipient(mode, session.RecipientKey, session.SenderPublicKey, HpkeKdf.HkdfSha512, HpkeAead.ChaCha20Poly1305, session.Enc, Info, Psk, PskId), "KDF")
		];

		if (mode.HasPsk())
		{
			others.Add((TryCreateRecipient(mode, session.RecipientKey, session.SenderPublicKey, HpkeKdf.HkdfSha256, HpkeAead.ChaCha20Poly1305, session.Enc, Info, otherPsk, PskId), "PSK"));
			others.Add((TryCreateRecipient(mode, session.RecipientKey, session.SenderPublicKey, HpkeKdf.HkdfSha256, HpkeAead.ChaCha20Poly1305, session.Enc, Info, Psk, [.. PskId, 0]), "PSK ID"));
		}

		if (mode.IsAuthenticated())
		{
			others.Add((TryCreateRecipient(mode, session.RecipientKey, otherSender, HpkeKdf.HkdfSha256, HpkeAead.ChaCha20Poly1305, session.Enc, Info, Psk, PskId), "sender"));
		}

		try
		{
			using (Assert.Multiple())
			{
				foreach ((HpkeRecipientContext? context, string change) in others)
				{
					HpkeRecipientContext created = await Assert.That(context).IsNotNull();
					await Assert.That(Open(created, ciphertext, [])).IsNull().Because(change);
					await Assert.That(Export(created, Info, 32)).IsNotEquivalentTo(Export(session.Sender, Info, 32)).Because(change);
				}
			}
		}
		finally
		{
			foreach ((HpkeRecipientContext? context, _) in others)
			{
				context?.Dispose();
			}
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task InvalidEncapsulatedKeysSetUpNothing([Matrix] HpkeTestMode mode)
	{
		using TKem recipient = TKem.GenerateKey();
		using TKem sender = TKem.GenerateKey();
		byte[] enc = new byte[TKem.CiphertextLength];
		using HpkeSenderContext context = CreateSender(mode, recipient, sender, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, enc, Info, Psk, PskId);

		using (Assert.Multiple())
		{
			foreach (byte[] invalid in (byte[][])[[], Resize(enc, -1), Resize(enc, 1), .. KemCiphertextChecks.Of<TKem>().InvalidCiphertexts])
			{
				await Assert.That(TryCreateRecipient(mode, recipient, sender, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, invalid, Info, Psk, PskId)).IsNull();
			}
		}
	}

	// VerifyPSKInputs of RFC 9180, Section 5.1, with the minimum length that this library sets. The checks come before encapsulation.
	[Test]
	public async Task PskInputsAreChecked()
	{
		using TKem recipient = TKem.GenerateKey();
		using TKem sender = TKem.GenerateKey();
		byte[] enc = CreateGuardedBuffer(0, TKem.CiphertextLength);
		(byte[] Psk, byte[] PskId, string ParameterName)[] invalid = [([], PskId, "psk"), (new byte[31], PskId, "psk"), (Psk, [], "pskId"), ([], [], "psk")];

		using (Assert.Multiple())
		{
			foreach ((byte[] psk, byte[] pskId, string parameterName) in invalid)
			{
				foreach (HpkeTestMode mode in (HpkeTestMode[])[HpkeTestMode.Psk, HpkeTestMode.AuthPsk])
				{
					await Assert.That(() => CreateSender(mode, recipient, sender, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, enc, Info, psk, pskId)).ThrowsExactly<ArgumentException>().WithParameterName(parameterName);
					await Assert.That(() => TryCreateRecipient(mode, recipient, sender, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, new byte[TKem.CiphertextLength], Info, psk, pskId)).ThrowsExactly<ArgumentException>().WithParameterName(parameterName);
				}
			}

			await Assert.That(enc).All(static value => value is DestinationSentinel);
		}

		// The shortest inputs that pass.
		byte[] shortest = new byte[TKem.CiphertextLength];
		using HpkeSenderContext context = HpkeSenderContext.Create(recipient, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, shortest, Info, new byte[32], [0]);
		using HpkeRecipientContext? opened = TryCreateRecipient(HpkeTestMode.Psk, recipient, null, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, shortest, Info, new byte[32], [0]);
		HpkeRecipientContext created = await Assert.That(opened).IsNotNull();
		await Assert.That(Open(created, Seal(context, Info, []), [])).IsEquivalentTo(Info, CollectionOrdering.Matching);
	}

	[Test]
	public async Task UnsupportedAlgorithmsThrow()
	{
		using TKem recipient = TKem.GenerateKey();
		byte[] enc = CreateGuardedBuffer(0, TKem.CiphertextLength);

		using (Assert.Multiple())
		{
			foreach (HpkeKdf kdf in (HpkeKdf[])[0, (HpkeKdf)4])
			{
				await Assert.That(() => HpkeSenderContext.Create(recipient, kdf, HpkeAead.Aes128Gcm, enc)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("kdf");
				await Assert.That(() => HpkeRecipientContext.TryCreate(recipient, kdf, HpkeAead.Aes128Gcm, enc.AsSpan(0, TKem.CiphertextLength), Info, out _)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("kdf");
			}

			foreach (HpkeAead aead in (HpkeAead[])[0, (HpkeAead)4, (HpkeAead)0xFFFE])
			{
				await Assert.That(() => HpkeSenderContext.Create(recipient, HpkeKdf.HkdfSha256, aead, enc)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("aead");
				await Assert.That(() => HpkeRecipientContext.TryCreate(recipient, HpkeKdf.HkdfSha256, aead, enc.AsSpan(0, TKem.CiphertextLength), Info, out _)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("aead");
			}

			await Assert.That(enc).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	public async Task KeysAndBuffersOfTheSetupAreChecked()
	{
		using TKem recipient = TKem.GenerateKey();
		using TKem recipientPublic = TKem.ImportEncapsulationKey(ExportEncapsulationKey(recipient));
		TKem disposed = TKem.GenerateKey();
		disposed.Dispose();
		int length = TKem.CiphertextLength;
		byte[] shortEnc = ShortBuffer(length, 1);
		byte[] overlapping = CreateGuardedBuffer(0, length + Info.Length);

		using (Assert.Multiple())
		{
			await Assert.That(() => HpkeSenderContext.Create<TKem>(null!, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, new byte[length])).ThrowsExactly<ArgumentNullException>().WithParameterName("recipient");
			await Assert.That(() => HpkeSenderContext.CreateAuthenticated(recipientPublic, null!, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, new byte[length])).ThrowsExactly<ArgumentNullException>().WithParameterName("sender");
			await Assert.That(() => HpkeRecipientContext.TryCreate<TKem>(null!, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, new byte[length], Info, out _)).ThrowsExactly<ArgumentNullException>().WithParameterName("recipient");
			await Assert.That(() => HpkeRecipientContext.TryCreateAuthenticated(recipient, null!, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, new byte[length], Info, out _)).ThrowsExactly<ArgumentNullException>().WithParameterName("sender");
			await Assert.That(() => HpkeSenderContext.CreateAuthenticated(recipientPublic, recipientPublic, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, new byte[length])).ThrowsExactly<ArgumentException>().WithParameterName("sender");
			await Assert.That(() => HpkeRecipientContext.TryCreate(recipientPublic, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, new byte[length], Info, out _)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => HpkeSenderContext.Create(disposed, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, new byte[length])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => HpkeRecipientContext.TryCreate(disposed, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, new byte[length], Info, out _)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => HpkeSenderContext.Create(recipientPublic, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, shortEnc)).Throws<ArgumentException>().WithParameterName("encapsulatedKey");
			await Assert.That(() => HpkeSenderContext.Create(recipientPublic, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, overlapping.AsSpan(0, length), overlapping.AsSpan(length - 1, Info.Length))).Throws<ArgumentException>().WithParameterName("encapsulatedKey");
			await Assert.That(() => HpkeSenderContext.Create(recipientPublic, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, overlapping.AsSpan(1, length), overlapping.AsSpan(0, Info.Length), Psk, PskId)).Throws<ArgumentException>().WithParameterName("encapsulatedKey");
			await Assert.That(shortEnc).All(static value => value is DestinationSentinel);
			await Assert.That(overlapping).All(static value => value is DestinationSentinel);
		}

		// A longer buffer receives the encapsulated key at its start.
		byte[] longer = CreateGuardedBuffer(1, length);
		using HpkeSenderContext context = HpkeSenderContext.Create(recipientPublic, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, longer.AsSpan(1), Info);
		using HpkeRecipientContext? opened = TryCreateRecipient(HpkeTestMode.Base, recipient, null, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, longer.AsSpan(1, length), Info, [], []);
		HpkeRecipientContext created = await Assert.That(opened).IsNotNull();

		using (Assert.Multiple())
		{
			await Assert.That(longer[0]).IsEqualTo(DestinationSentinel);
			await Assert.That(longer.AsSpan(1 + length).ToArray()).All(static value => value is DestinationSentinel);
			await Assert.That(Open(created, Seal(context, Info, []), [])).IsEquivalentTo(Info, CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task SealAndOpenCheckTheirBuffers()
	{
		using Session session = new(HpkeTestMode.Base, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm);
		const int tagSize = 16;
		byte[] message = CreateDeterministicSource(33);
		int length = message.Length + tagSize;
		byte[] shortCiphertext = ShortBuffer(length, 1);
		byte[] overlapping = CreateGuardedBuffer(0, length + 1);
		message.CopyTo(overlapping, 1);

		using (Assert.Multiple())
		{
			await Assert.That(() => session.Sender.Seal(message, shortCiphertext)).Throws<ArgumentException>().WithParameterName("ciphertext");
			await Assert.That(() => session.Sender.Seal(overlapping.AsSpan(1, message.Length), overlapping)).Throws<ArgumentException>().WithParameterName("ciphertext");
			await Assert.That(shortCiphertext).All(static value => value is DestinationSentinel);
			await Assert.That(session.Sender.SequenceNumber).IsEqualTo(0UL);
		}

		// Sealing in place, then into a longer buffer.
		byte[] inPlace = [.. message, .. new byte[tagSize]];
		int written = session.Sender.Seal(inPlace.AsSpan(0, message.Length), inPlace);
		byte[] longer = CreateGuardedBuffer(1, length);
		int longerWritten = session.Sender.Seal(message, longer.AsSpan(1));

		using (Assert.Multiple())
		{
			await Assert.That((written, longerWritten)).IsEqualTo((length, length));
			await Assert.That(longer[0]).IsEqualTo(DestinationSentinel);
			await Assert.That(longer.AsSpan(1 + length).ToArray()).All(static value => value is DestinationSentinel);
		}

		byte[] shortPlaintext = ShortBuffer(message.Length, 1);
		byte[] overlappingCiphertext = [0, .. inPlace];

		using (Assert.Multiple())
		{
			await Assert.That(() => session.Recipient.TryOpen(inPlace, shortPlaintext)).Throws<ArgumentException>().WithParameterName("plaintext");
			await Assert.That(() => session.Recipient.TryOpen(overlappingCiphertext.AsSpan(1), overlappingCiphertext)).Throws<ArgumentException>().WithParameterName("plaintext");
			await Assert.That(shortPlaintext).All(static value => value is DestinationSentinel);
			await Assert.That(session.Recipient.SequenceNumber).IsEqualTo(0UL);
		}

		// Opening in place, then into a longer buffer.
		bool opened = session.Recipient.TryOpen(inPlace, inPlace);
		byte[] longerPlaintext = CreateGuardedBuffer(0, message.Length);
		bool longerOpened = session.Recipient.TryOpen(longer.AsSpan(1, length), longerPlaintext);

		using (Assert.Multiple())
		{
			await Assert.That((opened, longerOpened)).IsEqualTo((true, true));
			await Assert.That(inPlace.AsSpan(0, message.Length).ToArray()).IsEquivalentTo(message, CollectionOrdering.Matching);
			await Assert.That(longerPlaintext.AsSpan(0, message.Length).ToArray()).IsEquivalentTo(message, CollectionOrdering.Matching);
			await Assert.That(longerPlaintext.AsSpan(message.Length).ToArray()).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task ExportsCheckTheirLengthAndMayOverlapTheirContext([Matrix] HpkeKdf kdf)
	{
		using Session session = new(HpkeTestMode.Base, kdf, HpkeAead.ExportOnly);
		int hashLength = kdf.HashLength;
		byte[] exporterContext = CreateDeterministicSource(40);

		using (Assert.Multiple())
		{
			await Assert.That(() => session.Sender.Export(exporterContext, new byte[255 * hashLength + 1])).Throws<ArgumentOutOfRangeException>().WithParameterName("destination");
			await Assert.That(() => session.Recipient.Export(exporterContext, new byte[255 * hashLength + 1])).Throws<ArgumentOutOfRangeException>().WithParameterName("destination");
			await Assert.That(() => session.Sender.Export(exporterContext, [])).ThrowsNothing();
			await Assert.That(() => session.Recipient.Export(exporterContext, [])).ThrowsNothing();

			foreach (int length in (int[])[16, hashLength, hashLength + 1, 3 * hashLength])
			{
				byte[] expected = Export(session.Sender, exporterContext, length);

				foreach (int offset in (int[])[0, 1, 39])
				{
					byte[] buffer = new byte[Math.Max(exporterContext.Length, offset + length)];
					exporterContext.CopyTo(buffer, 0);
					session.Recipient.Export(buffer.AsSpan(0, exporterContext.Length), buffer.AsSpan(offset, length));
					await Assert.That(buffer.AsSpan(offset, length).ToArray()).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"{length} bytes at offset {offset}");
				}
			}
		}
	}

	// The sender's limit is the same code, but its sequence number cannot be set.
	[Test]
	public async Task OpeningStopsAtTheMessageLimit()
	{
		using Session session = new(HpkeTestMode.Base, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm);
		byte[] ciphertext = Seal(session.Sender, Info, []);
		byte[] plaintext = CreateGuardedBuffer(0, Info.Length);
		session.Recipient.SequenceNumber = ulong.MaxValue - 1;
		bool openedBelowTheLimit = session.Recipient.TryOpen(ciphertext, plaintext);
		PrepareDestination(plaintext);
		session.Recipient.SequenceNumber = ulong.MaxValue;

		using (Assert.Multiple())
		{
			await Assert.That(openedBelowTheLimit).IsFalse();
			await Assert.That(() => session.Recipient.TryOpen(ciphertext, plaintext)).ThrowsExactly<CryptographicException>();
			await Assert.That(session.Recipient.SequenceNumber).IsEqualTo(ulong.MaxValue);
			await Assert.That(plaintext).All(static value => value is DestinationSentinel);
			await Assert.That(Export(session.Recipient, Info, 32)).IsEquivalentTo(Export(session.Sender, Info, 32), CollectionOrdering.Matching);
		}

		session.Recipient.SequenceNumber = 0;
		await Assert.That(Open(session.Recipient, ciphertext, [])).IsEquivalentTo(Info, CollectionOrdering.Matching);
	}

	[Test]
	public async Task DisposedContextsThrow()
	{
		Session session = new(HpkeTestMode.Base, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm);
		HpkeSenderContext sender = session.Sender;
		HpkeRecipientContext recipient = session.Recipient;
		session.Dispose();
		sender.Dispose();
		recipient.Dispose();
		byte[] buffer = new byte[64];

		using (Assert.Multiple())
		{
			await Assert.That(() => sender.Kdf).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => sender.Aead).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => sender.SequenceNumber).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => sender.Seal([], buffer)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => sender.Export([], buffer)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => recipient.Kdf).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => recipient.Aead).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => recipient.SequenceNumber).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => recipient.SequenceNumber = 1).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => recipient.TryOpen(buffer, buffer)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => recipient.Export([], buffer)).ThrowsExactly<ObjectDisposedException>();
		}
	}

	// The keys of both parties, as each holds them, and a pair of contexts set up from them.
	private sealed class Session : IDisposable
	{
		private readonly HpkeTestMode _mode;
		private readonly HpkeKdf _kdf;
		private readonly HpkeAead _aead;
		private readonly TKem _senderKey = TKem.GenerateKey();
		private readonly TKem _recipientPublicKey;

		public Session(HpkeTestMode mode, HpkeKdf kdf, HpkeAead aead)
		{
			_mode = mode;
			_kdf = kdf;
			_aead = aead;
			_recipientPublicKey = TKem.ImportEncapsulationKey(ExportEncapsulationKey(RecipientKey));
			SenderPublicKey = TKem.ImportEncapsulationKey(ExportEncapsulationKey(_senderKey));
			Sender = CreateSender(mode, _recipientPublicKey, _senderKey, kdf, aead, Enc, Info, Psk, PskId);
			Recipient = SetUpRecipientAgain();
		}

		public TKem RecipientKey { get; } = TKem.GenerateKey();

		public TKem SenderPublicKey { get; }

		public byte[] Enc { get; } = new byte[TKem.CiphertextLength];

		public HpkeSenderContext Sender { get; }

		public HpkeRecipientContext Recipient { get; }

		public HpkeRecipientContext SetUpRecipientAgain()
		{
			return TryCreateRecipient(_mode, RecipientKey, SenderPublicKey, _kdf, _aead, Enc, Info, Psk, PskId) ?? throw new InvalidOperationException("The recipient context was not set up.");
		}

		public void Dispose()
		{
			Sender.Dispose();
			Recipient.Dispose();
			_senderKey.Dispose();
			_recipientPublicKey.Dispose();
			RecipientKey.Dispose();
			SenderPublicKey.Dispose();
		}
	}
}
