namespace CryptoBase.SM2;

/// <summary>
/// Identifies the role of a party in the SM2 key exchange of GB/T 32918.3-2016.
/// </summary>
public enum SM2KeyExchangeRole
{
	/// <summary>
	/// The initiator, user A of GB/T 32918.3-2016, which sends its ephemeral public key first.
	/// </summary>
	Initiator,

	/// <summary>
	/// The responder, user B of GB/T 32918.3-2016.
	/// </summary>
	Responder
}
