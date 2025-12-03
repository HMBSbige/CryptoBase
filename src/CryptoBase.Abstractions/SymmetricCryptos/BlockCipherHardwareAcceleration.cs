namespace CryptoBase.Abstractions.SymmetricCryptos;

[Flags]
public enum BlockCipherHardwareAcceleration
{
	Unknown = 0,
	Block1 = 1 << 0,
	Block2 = 1 << 1,
	Block4 = 1 << 2,
	Block8 = 1 << 3,
	Block8V256 = 1 << 4,
	Block16V256 = 1 << 5,
	Block32V256 = 1 << 6,
	Block16V512 = 1 << 7,
	Block32V512 = 1 << 8,
	Block64V512 = 1 << 9
}
