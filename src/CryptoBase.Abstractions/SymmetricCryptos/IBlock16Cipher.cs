namespace CryptoBase.Abstractions.SymmetricCryptos;

public interface IBlock16Cipher<out TSelf> : ISymmetricCrypto where TSelf : IBlock16Cipher<TSelf>
{
	static abstract bool IsSupported { get; }

	static abstract BlockCryptoHardwareAcceleration HardwareAcceleration { get; }

	static abstract TSelf Create(in ReadOnlySpan<byte> key);

	VectorBuffer16 Encrypt(scoped in VectorBuffer16 source);
	VectorBuffer16 Decrypt(scoped in VectorBuffer16 source);

	VectorBuffer32 Encrypt(scoped in VectorBuffer32 source);
	VectorBuffer32 Decrypt(scoped in VectorBuffer32 source);

	VectorBuffer64 Encrypt(scoped in VectorBuffer64 source);
	VectorBuffer64 Decrypt(scoped in VectorBuffer64 source);

	VectorBuffer128 Encrypt(scoped in VectorBuffer128 source);
	VectorBuffer128 Decrypt(scoped in VectorBuffer128 source);

	VectorBuffer256 Encrypt(scoped in VectorBuffer256 source);
	VectorBuffer256 Decrypt(scoped in VectorBuffer256 source);

	VectorBuffer512 Encrypt(scoped in VectorBuffer512 source);
	VectorBuffer512 Decrypt(scoped in VectorBuffer512 source);
}
