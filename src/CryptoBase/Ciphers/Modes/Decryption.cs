namespace CryptoBase.Ciphers.Modes;

internal readonly struct Decryption : IBlockDirection
{
	public static bool IsDecrypt => true;
}
