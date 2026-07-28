namespace CryptoBase.Abstractions.SymmetricCryptos;

public interface IBlock16Cipher<out TSelf> : ISymmetricCrypto where TSelf : IBlock16Cipher<TSelf>
{
	static abstract bool IsSupported { get; }

	static abstract BlockCipherHardwareAcceleration HardwareAcceleration { get; }

	static abstract TSelf Create(in ReadOnlySpan<byte> key);

	VectorBuffer16 Encrypt(in VectorBuffer16 source);
	VectorBuffer16 Decrypt(in VectorBuffer16 source);

	VectorBuffer32 Encrypt(in VectorBuffer32 source);
	VectorBuffer32 Decrypt(in VectorBuffer32 source);

	VectorBuffer64 Encrypt(in VectorBuffer64 source);
	VectorBuffer64 Decrypt(in VectorBuffer64 source);

	VectorBuffer128 Encrypt(in VectorBuffer128 source);
	VectorBuffer128 Decrypt(in VectorBuffer128 source);

	VectorBuffer128 EncryptV256(in VectorBuffer128 source);
	VectorBuffer128 DecryptV256(in VectorBuffer128 source);

	VectorBuffer256 EncryptV256(in VectorBuffer256 source);
	VectorBuffer256 DecryptV256(in VectorBuffer256 source);

	VectorBuffer256 EncryptV512(in VectorBuffer256 source);
	VectorBuffer256 DecryptV512(in VectorBuffer256 source);

	VectorBuffer512 EncryptV512(in VectorBuffer512 source);
	VectorBuffer512 DecryptV512(in VectorBuffer512 source);
}
