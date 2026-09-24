namespace CryptoBase.Ciphers.Blocks.Aes;

internal interface IAesVectorCore
{
	Vector128<byte> Encrypt(Vector128<byte> source);

	void Encrypt2(ref Vector128<byte> v0, ref Vector128<byte> v1);

	void Encrypt4(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3);

	void Encrypt8(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7);

	Vector128<byte> Decrypt(Vector128<byte> source);

	void Decrypt2(ref Vector128<byte> v0, ref Vector128<byte> v1);

	void Decrypt4(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3);

	void Decrypt8(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7);
}
