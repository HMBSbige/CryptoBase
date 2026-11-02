using CryptoBase.Hpke;

namespace CryptoBase.Tests.Hpke;

public enum HpkeTestMode
{
	Base,
	Psk,
	Auth,
	AuthPsk
}

internal static class HpkeTestUtils
{
	public static bool IsAuthenticated(this HpkeTestMode mode)
	{
		return mode is HpkeTestMode.Auth or HpkeTestMode.AuthPsk;
	}

	public static bool HasPsk(this HpkeTestMode mode)
	{
		return mode is HpkeTestMode.Psk or HpkeTestMode.AuthPsk;
	}

	public static (byte[] Enc, byte[] SharedSecret) AuthEncapsulate<TKem>(TKem recipient, TKem sender) where TKem : class, IHpkeAuthKem<TKem>
	{
		byte[] enc = new byte[TKem.CiphertextLength];
		byte[] sharedSecret = new byte[TKem.SharedSecretLength];
		recipient.AuthEncapsulate(sender, enc, sharedSecret);
		return (enc, sharedSecret);
	}

	// Output starts filled with DestinationSentinel, so a false result can be checked to leave it unchanged.
	public static (bool Result, byte[] Output) TryAuthDecapsulate<TKem>(TKem recipient, ReadOnlySpan<byte> enc, TKem sender) where TKem : class, IHpkeAuthKem<TKem>
	{
		byte[] output = TestUtils.CreateGuardedBuffer(0, TKem.SharedSecretLength, 0);
		bool result = recipient.TryAuthDecapsulate(enc, sender, output);
		return (result, output);
	}

	// The known-answer hooks of the DHKEM types, which no interface declares.
	public static (byte[] Enc, byte[] SharedSecret) Encapsulate<TKem>(TKem recipient, byte[] ephemeralInputKeyMaterial) where TKem : class, IHpkeAuthKem<TKem>
	{
		byte[] enc = new byte[TKem.CiphertextLength];
		byte[] sharedSecret = new byte[TKem.SharedSecretLength];

		switch (recipient)
		{
			case DhKemP256 kem:
				kem.Encapsulate(ephemeralInputKeyMaterial, enc, sharedSecret);
				break;
			case DhKemP384 kem:
				kem.Encapsulate(ephemeralInputKeyMaterial, enc, sharedSecret);
				break;
			case DhKemP521 kem:
				kem.Encapsulate(ephemeralInputKeyMaterial, enc, sharedSecret);
				break;
			case DhKemX25519 kem:
				kem.Encapsulate(ephemeralInputKeyMaterial, enc, sharedSecret);
				break;
			default:
				throw new NotSupportedException(typeof(TKem).Name);
		}

		return (enc, sharedSecret);
	}

	public static (byte[] Enc, byte[] SharedSecret) AuthEncapsulate<TKem>(TKem recipient, TKem sender, byte[] ephemeralInputKeyMaterial) where TKem : class, IHpkeAuthKem<TKem>
	{
		byte[] enc = new byte[TKem.CiphertextLength];
		byte[] sharedSecret = new byte[TKem.SharedSecretLength];

		switch (recipient, sender)
		{
			case (DhKemP256 r, DhKemP256 s):
				r.AuthEncapsulate(ephemeralInputKeyMaterial, s, enc, sharedSecret);
				break;
			case (DhKemP384 r, DhKemP384 s):
				r.AuthEncapsulate(ephemeralInputKeyMaterial, s, enc, sharedSecret);
				break;
			case (DhKemP521 r, DhKemP521 s):
				r.AuthEncapsulate(ephemeralInputKeyMaterial, s, enc, sharedSecret);
				break;
			case (DhKemX25519 r, DhKemX25519 s):
				r.AuthEncapsulate(ephemeralInputKeyMaterial, s, enc, sharedSecret);
				break;
			default:
				throw new NotSupportedException(typeof(TKem).Name);
		}

		return (enc, sharedSecret);
	}

	// sender is used only in the authenticated modes, which need it.
	public static HpkeSenderContext CreateSender<TKem>(HpkeTestMode mode, TKem recipient, TKem? sender, HpkeKdf kdf, HpkeAead aead, byte[] encapsulatedKey, byte[] info, byte[] psk, byte[] pskId) where TKem : class, IHpkeAuthKem<TKem>
	{
		return mode switch
		{
			HpkeTestMode.Base => HpkeSenderContext.Create(recipient, kdf, aead, encapsulatedKey, info),
			HpkeTestMode.Psk => HpkeSenderContext.Create(recipient, kdf, aead, encapsulatedKey, info, psk, pskId),
			HpkeTestMode.Auth => HpkeSenderContext.CreateAuthenticated(recipient, Required(sender), kdf, aead, encapsulatedKey, info),
			_ => HpkeSenderContext.CreateAuthenticated(recipient, Required(sender), kdf, aead, encapsulatedKey, info, psk, pskId)
		};
	}

	public static HpkeRecipientContext? TryCreateRecipient<TKem>(HpkeTestMode mode, TKem recipient, TKem? sender, HpkeKdf kdf, HpkeAead aead, ReadOnlySpan<byte> encapsulatedKey, byte[] info, byte[] psk, byte[] pskId) where TKem : class, IHpkeAuthKem<TKem>
	{
		HpkeRecipientContext? context;
		bool created = mode switch
		{
			HpkeTestMode.Base => HpkeRecipientContext.TryCreate(recipient, kdf, aead, encapsulatedKey, info, out context),
			HpkeTestMode.Psk => HpkeRecipientContext.TryCreate(recipient, kdf, aead, encapsulatedKey, info, psk, pskId, out context),
			HpkeTestMode.Auth => HpkeRecipientContext.TryCreateAuthenticated(recipient, Required(sender), kdf, aead, encapsulatedKey, info, out context),
			_ => HpkeRecipientContext.TryCreateAuthenticated(recipient, Required(sender), kdf, aead, encapsulatedKey, info, psk, pskId, out context)
		};

		return created != context is not null ? throw new InvalidOperationException("The result disagrees with the context.") : context;
	}

	public static byte[] Seal(HpkeSenderContext context, byte[] plaintext, byte[] associatedData)
	{
		byte[] ciphertext = new byte[plaintext.Length + context.Aead.TagSize];
		int written = context.Seal(plaintext, ciphertext, associatedData);
		return written == ciphertext.Length ? ciphertext : throw new InvalidOperationException($"Seal wrote {written} bytes.");
	}

	// null if the ciphertext does not open.
	public static byte[]? Open(HpkeRecipientContext context, byte[] ciphertext, byte[] associatedData)
	{
		byte[] plaintext = new byte[Math.Max(0, ciphertext.Length - context.Aead.TagSize)];
		return context.TryOpen(ciphertext, plaintext, associatedData) ? plaintext : null;
	}

	public static byte[] Export(HpkeSenderContext context, byte[] exporterContext, int length)
	{
		byte[] secret = new byte[length];
		context.Export(exporterContext, secret);
		return secret;
	}

	public static byte[] Export(HpkeRecipientContext context, byte[] exporterContext, int length)
	{
		byte[] secret = new byte[length];
		context.Export(exporterContext, secret);
		return secret;
	}

	private static T Required<T>(T? value) where T : class
	{
		return value ?? throw new ArgumentNullException(nameof(value), "The authenticated modes need a sender.");
	}
}
