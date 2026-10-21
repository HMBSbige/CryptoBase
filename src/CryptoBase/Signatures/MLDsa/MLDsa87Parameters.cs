namespace CryptoBase.Signatures.MLDsa;

internal readonly struct MLDsa87Parameters : IMLDsaParameters
{
	public static int K => 8;

	public static int L => 7;

	public static int Eta => 2;

	public static int Tau => 60;

	public static int Lambda => 256;

	public static int Gamma1Bits => 19;

	public static int Gamma2 => MLDsaConstants.Gamma2Large;

	public static int Omega => 75;

	public static SignatureScheme Scheme => SignatureScheme.MLDsa87;

	// id-ml-dsa-87, 2.16.840.1.101.3.4.3.19.
	public static ReadOnlySpan<byte> AlgorithmIdentifier => [0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13];
}
