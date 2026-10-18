namespace CryptoBase.Kdf.Argon2;

internal readonly struct Argon2FirstPass : IArgon2Pass
{
	public static bool IsFirst => true;
}
