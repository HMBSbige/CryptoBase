namespace CryptoBase.X509;

/// <summary>
/// Describes the result of matching a host name against a certificate; see <see cref="Certificate.MatchHostName" />.
/// </summary>
/// <remarks>The default value is <see cref="Mismatch" />, so a result that is never set does not accept the host name.</remarks>
public enum HostNameMatch
{
	/// <summary>
	/// No entry of the subject alternative name extension identifies the host name, or the certificate has no such extension.
	/// </summary>
	Mismatch = 0,

	/// <summary>
	/// An entry of the subject alternative name extension identifies the host name.
	/// </summary>
	Match = 1,

	/// <summary>
	/// The subject alternative name extension does not decode, so the certificate is malformed.
	/// </summary>
	MalformedExtension = 2
}
