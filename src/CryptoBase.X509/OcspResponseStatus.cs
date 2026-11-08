namespace CryptoBase.X509;

/// <summary>
/// Specifies the status of an OCSP response (RFC 6960, Sec. 4.2.1).
/// </summary>
public enum OcspResponseStatus
{
	/// <summary>
	/// The response has valid confirmations.
	/// </summary>
	Successful = 0,

	/// <summary>
	/// The request was not valid.
	/// </summary>
	MalformedRequest = 1,

	/// <summary>
	/// The responder reached an inconsistent internal state.
	/// </summary>
	InternalError = 2,

	/// <summary>
	/// The responder is temporarily unable to respond.
	/// </summary>
	TryLater = 3,

	/// <summary>
	/// The responder requires a signed request.
	/// </summary>
	SignatureRequired = 5,

	/// <summary>
	/// The client is not authorized to make the query, or the responder cannot answer authoritatively.
	/// </summary>
	Unauthorized = 6,
}
