namespace CryptoBase.X509;

/// <summary>
/// Represents the result of validating the certificates that a peer presented.
/// </summary>
/// <remarks>The default value is invalid, so a result that is never set rejects the certificates.</remarks>
public readonly struct CertificateValidationResult
{
	private CertificateValidationResult(bool isValid, CertificateValidationError error, string? message)
	{
		IsValid = isValid;
		Error = error;
		Message = message;
	}

	/// <summary>
	/// Gets a result that accepts the certificates.
	/// </summary>
	public static CertificateValidationResult Valid => new(true, CertificateValidationError.Unspecified, null);

	/// <summary>
	/// Gets a value that indicates whether the certificates are acceptable.
	/// </summary>
	public bool IsValid { get; }

	/// <summary>
	/// Gets why the certificates are not acceptable, or <see cref="CertificateValidationError.Unspecified" /> if they are.
	/// </summary>
	public CertificateValidationError Error { get; }

	/// <summary>
	/// Gets a description of the problem for diagnostics, or <see langword="null" />.
	/// </summary>
	public string? Message { get; }

	/// <summary>
	/// Creates a result that rejects the certificates.
	/// </summary>
	/// <param name="error">Why the certificates are not acceptable.</param>
	/// <param name="message">A description of the problem for diagnostics, or <see langword="null" />.</param>
	/// <returns>The result.</returns>
	public static CertificateValidationResult Invalid(CertificateValidationError error, string? message = null)
	{
		return new CertificateValidationResult(false, error, message);
	}
}
