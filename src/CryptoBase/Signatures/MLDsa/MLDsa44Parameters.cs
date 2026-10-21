namespace CryptoBase.Signatures.MLDsa;

internal readonly struct MLDsa44Parameters : IMLDsaParameters
{
	public static int K => 4;

	public static int L => 4;

	public static int Eta => 2;

	public static int Tau => 39;

	public static int Lambda => 128;

	public static int Gamma1Bits => 17;

	public static int Gamma2 => MLDsaConstants.Gamma2Small;

	public static int Omega => 80;

	public static SignatureScheme Scheme => SignatureScheme.MLDsa44;

	// id-ml-dsa-44, 2.16.840.1.101.3.4.3.17.
	public static ReadOnlySpan<byte> AlgorithmIdentifier => [0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11];
}
