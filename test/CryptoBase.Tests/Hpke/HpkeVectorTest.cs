using CryptoBase.Hpke;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.Hpke.HpkeTestUtils;
using static CryptoBase.Tests.Kems.KemTestUtils;

namespace CryptoBase.Tests.Hpke;

// Known-answer tests. The KEM and the key schedule are checked apart, through the internal hooks, so that vectors with a KEM or a key schedule alone count; the recipient is also checked end to end through the public API.
[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before the contexts are disposed.")]
public class HpkeVectorTest
{
	[Test]
	[MethodDataSource(typeof(HpkeVectors), nameof(HpkeVectors.Full))]
	[MethodDataSource(typeof(HpkeVectors), nameof(HpkeVectors.KemOnly))]
	public Task KeyPairsDeriveFromTheirInputKeyMaterial(HpkeVector vector)
	{
		return vector.KemId switch
		{
			0x0010 => KeyPairsDeriveFromTheirInputKeyMaterial<DhKemP256>(vector),
			0x0011 => KeyPairsDeriveFromTheirInputKeyMaterial<DhKemP384>(vector),
			0x0012 => KeyPairsDeriveFromTheirInputKeyMaterial<DhKemP521>(vector),
			0x0020 => KeyPairsDeriveFromTheirInputKeyMaterial<DhKemX25519>(vector),
			0x0021 => KeyPairsDeriveFromTheirInputKeyMaterial<DhKemX448>(vector),
			_ => throw new NotSupportedException(vector.ToString())
		};
	}

	[Test]
	[MethodDataSource(typeof(HpkeVectors), nameof(HpkeVectors.Full))]
	[MethodDataSource(typeof(HpkeVectors), nameof(HpkeVectors.KemOnly))]
	public Task EncapsulationsMatch(HpkeVector vector)
	{
		return vector.KemId switch
		{
			0x0010 => EncapsulationsMatch<DhKemP256>(vector),
			0x0011 => EncapsulationsMatch<DhKemP384>(vector),
			0x0012 => EncapsulationsMatch<DhKemP521>(vector),
			0x0020 => EncapsulationsMatch<DhKemX25519>(vector),
			0x0021 => EncapsulationsMatch<DhKemX448>(vector),
			_ => throw new NotSupportedException(vector.ToString())
		};
	}

	[Test]
	[MethodDataSource(typeof(HpkeVectors), nameof(HpkeVectors.Full))]
	public Task RecipientsOpenAndExport(HpkeVector vector)
	{
		return vector.KemId switch
		{
			0x0010 => RecipientsOpenAndExport<DhKemP256>(vector),
			0x0012 => RecipientsOpenAndExport<DhKemP521>(vector),
			0x0020 => RecipientsOpenAndExport<DhKemX25519>(vector),
			0x0021 => RecipientsOpenAndExport<DhKemX448>(vector),
			_ => throw new NotSupportedException(vector.ToString())
		};
	}

	[Test]
	[MethodDataSource(typeof(HpkeVectors), nameof(HpkeVectors.WithKeySchedule))]
	public async Task KeySchedulesSealOpenAndExport(HpkeVector vector)
	{
		(HpkeKdfId kdf, HpkeAeadId aead) = Suite(vector);
		using HpkeSenderContext sender = HpkeSenderContext.Create(vector.KemId, (HpkeMode)vector.Mode, kdf, aead, vector.SharedSecret, vector.Info, vector.Psk, vector.PskId);
		using HpkeRecipientContext recipient = HpkeRecipientContext.Create(vector.KemId, (HpkeMode)vector.Mode, kdf, aead, vector.SharedSecret, vector.Info, vector.Psk, vector.PskId);

		using (Assert.Multiple())
		{
			if (aead is HpkeAeadId.ExportOnly)
			{
				await Assert.That(vector.Encryptions).IsEmpty();
				await Assert.That(() => sender.Seal([], new byte[16])).ThrowsExactly<InvalidOperationException>();
				await Assert.That(() => recipient.TryOpen(new byte[16], [])).ThrowsExactly<InvalidOperationException>();
			}

			// The sender reaches each sequence number by sealing messages that the vector skips.
			foreach (HpkeEncryption encryption in vector.Encryptions)
			{
				while (sender.SequenceNumber < (ulong)encryption.Seq)
				{
					_ = Seal(sender, [], []);
				}

				await Assert.That(Seal(sender, encryption.Pt, encryption.Aad)).IsEquivalentTo(encryption.Ct, CollectionOrdering.Matching).Because($"sealing {encryption.Seq}");
			}

			await AssertOpens(recipient, vector);
			await AssertExports(sender.Export, vector);
			await AssertExports(recipient.Export, vector);
		}
	}

	private static async Task KeyPairsDeriveFromTheirInputKeyMaterial<TKem>(HpkeVector vector) where TKem : class, IHpkeAuthKem<TKem>
	{
		(byte[]? Ikm, byte[]? PrivateKey, byte[]? PublicKey)[] keyPairs = [(vector.IkmE, vector.SkEm, vector.PkEm ?? vector.Enc), (vector.IkmR, vector.SkRm, vector.PkRm), (vector.IkmS, vector.SkSm, vector.PkSm)];

		using (Assert.Multiple())
		{
			foreach ((byte[]? ikm, byte[]? privateKey, byte[]? publicKey) in keyPairs)
			{
				if (ikm is null)
				{
					continue;
				}

				using TKem kem = TKem.DeriveKeyPair(ikm);
				await Assert.That((kem.HasPrivateSeed, kem.HasDecapsulationKey)).IsEqualTo((false, true));
				await Assert.That(ExportEncapsulationKey(kem)).IsEquivalentTo(Required(publicKey), CollectionOrdering.Matching);

				if (privateKey is not null)
				{
					await Assert.That(ExportDecapsulationKey(kem)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
				}
			}
		}
	}

	private static async Task EncapsulationsMatch<TKem>(HpkeVector vector) where TKem : class, IHpkeAuthKem<TKem>
	{
		using TKem recipient = TKem.DeriveKeyPair(Required(vector.IkmR));
		using TKem? sender = vector.IsAuthenticated ? TKem.DeriveKeyPair(Required(vector.IkmS)) : null;
		byte[] ikmE = Required(vector.IkmE);
		(byte[] enc, byte[] sharedSecret) = sender is null ? Encapsulate(recipient, ikmE) : AuthEncapsulate(recipient, sender, ikmE);
		byte[] decapsulated = new byte[TKem.SharedSecretLength];
		bool result = sender is null ? recipient.TryDecapsulate(enc, decapsulated) : recipient.TryAuthDecapsulate(enc, sender, decapsulated);

		using (Assert.Multiple())
		{
			await Assert.That(enc).IsEquivalentTo(Required(vector.Enc), CollectionOrdering.Matching);
			await Assert.That(sharedSecret).IsEquivalentTo(vector.SharedSecret, CollectionOrdering.Matching);
			await Assert.That(result).IsTrue();
			await Assert.That(decapsulated).IsEquivalentTo(vector.SharedSecret, CollectionOrdering.Matching);
		}
	}

	private static async Task RecipientsOpenAndExport<TKem>(HpkeVector vector) where TKem : class, IHpkeAuthKem<TKem>
	{
		(HpkeKdfId kdf, HpkeAeadId aead) = Suite(vector);
		using TKem recipient = TKem.ImportDecapsulationKey(Required(vector.SkRm));
		using TKem? sender = vector.IsAuthenticated ? TKem.ImportEncapsulationKey(Required(vector.PkSm)) : null;
		using HpkeRecipientContext? context = TryCreateRecipient((HpkeTestMode)vector.Mode, recipient, sender, kdf, aead, Required(vector.Enc), vector.Info, vector.Psk, vector.PskId);

		HpkeRecipientContext created = await Assert.That(context).IsNotNull();

		using (Assert.Multiple())
		{
			await Assert.That((created.Kdf, created.Aead)).IsEqualTo((kdf, aead));
			await AssertOpens(created, vector);
			await AssertExports(created.Export, vector);
		}
	}

	// Each message opens at its own sequence number, set directly, as a recipient that sets up its context again does.
	private static async Task AssertOpens(HpkeRecipientContext context, HpkeVector vector)
	{
		foreach (HpkeEncryption encryption in vector.Encryptions)
		{
			context.SequenceNumber = (ulong)encryption.Seq;
			await Assert.That(Open(context, encryption.Ct, encryption.Aad)).IsEquivalentTo(encryption.Pt, CollectionOrdering.Matching).Because($"opening {encryption.Seq}");
			await Assert.That(context.SequenceNumber).IsEqualTo((ulong)encryption.Seq + 1);
		}
	}

	private static async Task AssertExports(Action<ReadOnlySpan<byte>, Span<byte>> export, HpkeVector vector)
	{
		await Assert.That(vector.Exports).IsNotEmpty();

		foreach (HpkeExport expected in vector.Exports)
		{
			byte[] secret = new byte[expected.L];
			export(expected.ExporterContext, secret);
			await Assert.That(secret).IsEquivalentTo(expected.ExportedValue, CollectionOrdering.Matching).Because($"exporting {Convert.ToHexString(expected.ExporterContext)}");
		}
	}

	private static (HpkeKdfId Kdf, HpkeAeadId Aead) Suite(HpkeVector vector)
	{
		return (vector.Kdf ?? throw new InvalidOperationException($"{vector} has no KDF."), vector.Aead ?? throw new InvalidOperationException($"{vector} has no AEAD."));
	}

	private static byte[] Required(byte[]? value)
	{
		return value ?? throw new InvalidOperationException("The vector lacks a value the test needs.");
	}
}
