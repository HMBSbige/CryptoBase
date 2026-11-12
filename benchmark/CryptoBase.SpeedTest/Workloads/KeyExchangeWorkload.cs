using CryptoBase.SM2;
using CryptoBase.SM9;

namespace CryptoBase.SpeedTest.Workloads;

/// <summary>
/// Runs the initiator's side of one complete SM2 key exchange per iteration: it creates the exchange, which draws an ephemeral key, exports
/// the ephemeral public key and derives a 16-byte key from the static and ephemeral public keys of the responder, without confirmations.
/// </summary>
internal sealed class SM2KeyExchangeWorkload : Workload
{
	private const int KeyLength = 16;

	private static readonly byte[] InitiatorId = "alice@example.com"u8.ToArray();
	private static readonly byte[] ResponderId = "bob@example.com"u8.ToArray();

	private readonly SM2Key _initiatorKey = SM2Key.GenerateKey();
	private readonly SM2Key _responderKey = SM2Key.GenerateKey();
	private readonly SM2Key _initiatorPublicKey;
	private readonly SM2Key _responderPublicKey;
	private readonly byte[] _responderEphemeralPublicKey = new byte[SM2KeyExchange.EphemeralPublicKeyLength];
	private readonly byte[] _ephemeralPublicKey = new byte[SM2KeyExchange.EphemeralPublicKeyLength];
	private readonly byte[] _sharedKey = new byte[KeyLength];

	public SM2KeyExchangeWorkload()
	{
		_initiatorPublicKey = PublicKeyOf(_initiatorKey);
		_responderPublicKey = PublicKeyOf(_responderKey);

		using SM2KeyExchange responder = SM2KeyExchange.Create(_responderKey, ResponderId, SM2KeyExchangeRole.Responder);
		responder.ExportEphemeralPublicKey(_responderEphemeralPublicKey);
	}

	public override void Verify()
	{
		using SM2KeyExchange initiator = SM2KeyExchange.Create(_initiatorKey, InitiatorId, SM2KeyExchangeRole.Initiator);
		using SM2KeyExchange responder = SM2KeyExchange.Create(_responderKey, ResponderId, SM2KeyExchangeRole.Responder);
		byte[] initiatorEphemeral = new byte[SM2KeyExchange.EphemeralPublicKeyLength];
		byte[] responderEphemeral = new byte[SM2KeyExchange.EphemeralPublicKeyLength];
		initiator.ExportEphemeralPublicKey(initiatorEphemeral);
		responder.ExportEphemeralPublicKey(responderEphemeral);

		byte[] initiatorKey = new byte[KeyLength];
		byte[] responderKey = new byte[KeyLength];
		byte[] initiatorConfirmation = new byte[SM2KeyExchange.ConfirmationLength];
		byte[] responderConfirmation = new byte[SM2KeyExchange.ConfirmationLength];
		byte[] expectedFromInitiator = new byte[SM2KeyExchange.ConfirmationLength];
		byte[] expectedFromResponder = new byte[SM2KeyExchange.ConfirmationLength];

		SelfTestException.ThrowIfFalse(responder.TryDeriveKey(_initiatorPublicKey, InitiatorId, initiatorEphemeral, responderKey, responderConfirmation, expectedFromInitiator), "The responder rejected a valid ephemeral key.");
		SelfTestException.ThrowIfFalse(initiator.TryDeriveKey(_responderPublicKey, ResponderId, responderEphemeral, initiatorKey, initiatorConfirmation, expectedFromResponder), "The initiator rejected a valid ephemeral key.");
		SelfTestException.ThrowIfNotEqual(initiatorKey, responderKey, "The two parties derived different keys.");
		SelfTestException.ThrowIfNotEqual(responderConfirmation, expectedFromResponder, "The confirmation of the responder does not match.");
		SelfTestException.ThrowIfNotEqual(initiatorConfirmation, expectedFromInitiator, "The confirmation of the initiator does not match.");
	}

	public override void Run(long iterations)
	{
		SM2Key key = _initiatorKey;
		SM2Key peerKey = _responderPublicKey;
		ReadOnlySpan<byte> peerEphemeralPublicKey = _responderEphemeralPublicKey;
		Span<byte> ephemeralPublicKey = _ephemeralPublicKey;
		Span<byte> sharedKey = _sharedKey;

		for (long i = 0; i < iterations; ++i)
		{
			using SM2KeyExchange exchange = SM2KeyExchange.Create(key, InitiatorId, SM2KeyExchangeRole.Initiator);
			exchange.ExportEphemeralPublicKey(ephemeralPublicKey);

			if (!exchange.TryDeriveKey(peerKey, ResponderId, peerEphemeralPublicKey, sharedKey))
			{
				SelfTestException.Throw("The initiator rejected a valid ephemeral key.");
			}
		}
	}

	public override void Dispose()
	{
		_initiatorKey.Dispose();
		_responderKey.Dispose();
		_initiatorPublicKey.Dispose();
		_responderPublicKey.Dispose();
	}

	private static SM2Key PublicKeyOf(SM2Key key)
	{
		byte[] publicKey = new byte[SM2Key.PublicKeyLength];
		key.ExportPublicKey(publicKey);
		return SM2Key.ImportPublicKey(publicKey);
	}
}

/// <summary>
/// Runs the initiator's side of one complete SM9 key exchange per iteration: it creates the exchange, which draws an ephemeral key, exports
/// the ephemeral public key and derives a 16-byte key from the ephemeral public key of the responder, without confirmations.
/// </summary>
internal sealed class SM9KeyExchangeWorkload : Workload
{
	private const int KeyLength = 16;

	private static readonly byte[] InitiatorId = "alice@example.com"u8.ToArray();
	private static readonly byte[] ResponderId = "bob@example.com"u8.ToArray();

	private readonly SM9KeyExchangeKey _initiatorKey;
	private readonly SM9KeyExchangeKey _responderKey;
	private readonly byte[] _responderEphemeralPublicKey = new byte[SM9KeyExchange.EphemeralPublicKeyLength];
	private readonly byte[] _ephemeralPublicKey = new byte[SM9KeyExchange.EphemeralPublicKeyLength];
	private readonly byte[] _sharedKey = new byte[KeyLength];

	public SM9KeyExchangeWorkload()
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		_initiatorKey = master.ExtractKeyExchangeKey(InitiatorId);
		_responderKey = master.ExtractKeyExchangeKey(ResponderId);

		using SM9KeyExchange responder = SM9KeyExchange.Create(_responderKey, InitiatorId, SM9KeyExchangeRole.Responder);
		responder.ExportEphemeralPublicKey(_responderEphemeralPublicKey);
	}

	public override void Verify()
	{
		using SM9KeyExchange initiator = SM9KeyExchange.Create(_initiatorKey, ResponderId, SM9KeyExchangeRole.Initiator);
		using SM9KeyExchange responder = SM9KeyExchange.Create(_responderKey, InitiatorId, SM9KeyExchangeRole.Responder);
		byte[] initiatorEphemeral = new byte[SM9KeyExchange.EphemeralPublicKeyLength];
		byte[] responderEphemeral = new byte[SM9KeyExchange.EphemeralPublicKeyLength];
		initiator.ExportEphemeralPublicKey(initiatorEphemeral);
		responder.ExportEphemeralPublicKey(responderEphemeral);

		byte[] initiatorKey = new byte[KeyLength];
		byte[] responderKey = new byte[KeyLength];
		byte[] initiatorConfirmation = new byte[SM9KeyExchange.ConfirmationLength];
		byte[] responderConfirmation = new byte[SM9KeyExchange.ConfirmationLength];
		byte[] expectedFromInitiator = new byte[SM9KeyExchange.ConfirmationLength];
		byte[] expectedFromResponder = new byte[SM9KeyExchange.ConfirmationLength];

		SelfTestException.ThrowIfFalse(responder.TryDeriveKey(initiatorEphemeral, responderKey, responderConfirmation, expectedFromInitiator), "The responder rejected a valid ephemeral key.");
		SelfTestException.ThrowIfFalse(initiator.TryDeriveKey(responderEphemeral, initiatorKey, initiatorConfirmation, expectedFromResponder), "The initiator rejected a valid ephemeral key.");
		SelfTestException.ThrowIfNotEqual(initiatorKey, responderKey, "The two parties derived different keys.");
		SelfTestException.ThrowIfNotEqual(responderConfirmation, expectedFromResponder, "The confirmation of the responder does not match.");
		SelfTestException.ThrowIfNotEqual(initiatorConfirmation, expectedFromInitiator, "The confirmation of the initiator does not match.");
	}

	public override void Run(long iterations)
	{
		SM9KeyExchangeKey key = _initiatorKey;
		ReadOnlySpan<byte> peerEphemeralPublicKey = _responderEphemeralPublicKey;
		Span<byte> ephemeralPublicKey = _ephemeralPublicKey;
		Span<byte> sharedKey = _sharedKey;

		for (long i = 0; i < iterations; ++i)
		{
			using SM9KeyExchange exchange = SM9KeyExchange.Create(key, ResponderId, SM9KeyExchangeRole.Initiator);
			exchange.ExportEphemeralPublicKey(ephemeralPublicKey);

			if (!exchange.TryDeriveKey(peerEphemeralPublicKey, sharedKey))
			{
				SelfTestException.Throw("The initiator rejected a valid ephemeral key.");
			}
		}
	}

	public override void Dispose()
	{
		_initiatorKey.Dispose();
		_responderKey.Dispose();
	}
}
