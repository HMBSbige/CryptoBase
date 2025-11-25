namespace CryptoBase.Abstractions.SymmetricCryptos;

public interface IBlockCrypto16 : IBlockCrypto
{
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
	VectorBuffer1024 Encrypt(scoped in VectorBuffer1024 source);
	VectorBuffer1024 Decrypt(scoped in VectorBuffer1024 source);
}
