namespace CryptoBase.Ciphers.Blocks.Aes;

internal readonly struct AesEncrypt : IAesOperation
{
	public static bool IsDecrypt => false;
}
