namespace CryptoBase.Abstractions.SymmetricCryptos;

[Flags]
public enum BlockCipherHardwareAcceleration
{
	Unknown = 0,
	Block1 = 1 << 0,
	Block2 = 1 << 1,
	Block4 = 1 << 2,
	Block8 = 1 << 3,
	Block16 = 1 << 4,
	Block32 = 1 << 5,
	Block64 = 1 << 6
}
