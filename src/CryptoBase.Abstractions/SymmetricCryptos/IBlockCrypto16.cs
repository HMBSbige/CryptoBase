namespace CryptoBase.Abstractions.SymmetricCryptos;

public interface IBlockCrypto16 : IBlockCrypto
{
	VectorBuffer16 Encrypt(VectorBuffer16 source);
	VectorBuffer16 Decrypt(VectorBuffer16 source);
	VectorBuffer32 Encrypt(VectorBuffer32 source);
	VectorBuffer32 Decrypt(VectorBuffer32 source);
	VectorBuffer64 Encrypt(VectorBuffer64 source);
	VectorBuffer64 Decrypt(VectorBuffer64 source);
	VectorBuffer128 Encrypt(VectorBuffer128 source);
	VectorBuffer128 Decrypt(VectorBuffer128 source);
	VectorBuffer256 Encrypt(VectorBuffer256 source);
	VectorBuffer256 Decrypt(VectorBuffer256 source);
	VectorBuffer512 Encrypt(VectorBuffer512 source);
	VectorBuffer512 Decrypt(VectorBuffer512 source);
	VectorBuffer1024 Encrypt(VectorBuffer1024 source);
	VectorBuffer1024 Decrypt(VectorBuffer1024 source);
}
