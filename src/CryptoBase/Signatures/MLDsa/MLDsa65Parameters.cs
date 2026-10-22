namespace CryptoBase.Signatures.MLDsa;

internal readonly struct MLDsa65Parameters : IMLDsaParameters
{
	public static int K => 6;

	public static int L => 5;

	public static int Eta => 4;

	public static int Tau => 49;

	public static int Lambda => 192;

	public static int Gamma1Bits => 19;

	public static int Gamma2 => MLDsaConstants.Gamma2Large;

	public static int Omega => 55;

	public static SignatureAlgorithm Algorithm => SignatureAlgorithm.MLDsa65;

	// id-ml-dsa-65, 2.16.840.1.101.3.4.3.18.
	public static ReadOnlySpan<byte> AlgorithmIdentifier => [0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];
}
