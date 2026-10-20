namespace CryptoBase.Kems.MLKem;

internal readonly struct MLKem512Parameters : IMLKemParameters
{
	public static int K => 2;

	public static int Eta1 => 3;

	public static int Du => 10;

	public static int Dv => 4;
}
