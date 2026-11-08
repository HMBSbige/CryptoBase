namespace CryptoBase.SM9;

/// <summary>
/// Identifies the role of a party in the SM9 key exchange of GB/T 38635.2-2020 (GM/T 0044.3-2016).
/// </summary>
public enum SM9KeyExchangeRole
{
	/// <summary>
	/// The initiator, user A of GM/T 0044.3, which sends its ephemeral public key first.
	/// </summary>
	Initiator,

	/// <summary>
	/// The responder, user B of GM/T 0044.3.
	/// </summary>
	Responder
}
