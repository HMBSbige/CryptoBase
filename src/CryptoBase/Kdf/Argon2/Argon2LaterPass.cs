namespace CryptoBase.Kdf.Argon2;

internal readonly struct Argon2LaterPass : IArgon2Pass
{
	public static bool IsFirst => false;
}
