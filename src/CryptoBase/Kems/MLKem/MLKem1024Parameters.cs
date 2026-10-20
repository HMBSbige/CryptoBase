namespace CryptoBase.Kems.MLKem;

internal readonly struct MLKem1024Parameters : IMLKemParameters
{
	public static int K => 4;

	public static int Eta1 => 2;

	public static int Du => 11;

	public static int Dv => 5;
}
