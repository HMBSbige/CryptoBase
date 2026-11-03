namespace CryptoBase.Signatures.Rsa;

// The secret fields of RSAPrivateKey (RFC 8017, Appendix A.1.2).
internal enum RsaPrivateComponent
{
	PrivateExponent,
	Prime1,
	Prime2,
	Exponent1,
	Exponent2,
	Coefficient
}
