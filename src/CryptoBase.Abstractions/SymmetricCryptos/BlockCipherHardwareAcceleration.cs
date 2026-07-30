namespace CryptoBase.Abstractions.SymmetricCryptos;

/// <summary>
/// Specifies the hardware-accelerated block-processing widths supported by a block cipher.
/// </summary>
[Flags]
public enum BlockCipherHardwareAcceleration
{
	/// <summary>
	/// No hardware-accelerated block operation is reported.
	/// </summary>
	Unknown = 0,

	/// <summary>
	/// Supports hardware-accelerated processing of one block at a time.
	/// </summary>
	Block1 = 1 << 0,

	/// <summary>
	/// Supports hardware-accelerated processing of two blocks at a time.
	/// </summary>
	Block2 = 1 << 1,

	/// <summary>
	/// Supports hardware-accelerated processing of four blocks at a time.
	/// </summary>
	Block4 = 1 << 2,

	/// <summary>
	/// Supports hardware-accelerated processing of eight blocks at a time.
	/// </summary>
	Block8 = 1 << 3,

	/// <summary>
	/// Supports hardware-accelerated processing of eight blocks using 256-bit vectors.
	/// </summary>
	Block8V256 = 1 << 4,

	/// <summary>
	/// Supports hardware-accelerated processing of 16 blocks using 256-bit vectors.
	/// </summary>
	Block16V256 = 1 << 5,

	/// <summary>
	/// Supports hardware-accelerated processing of 32 blocks using 256-bit vectors.
	/// </summary>
	Block32V256 = 1 << 6,

	/// <summary>
	/// Supports hardware-accelerated processing of 16 blocks using 512-bit vectors.
	/// </summary>
	Block16V512 = 1 << 7,

	/// <summary>
	/// Supports hardware-accelerated processing of 32 blocks using 512-bit vectors.
	/// </summary>
	Block32V512 = 1 << 8,

	/// <summary>
	/// Supports hardware-accelerated processing of 64 blocks using 512-bit vectors.
	/// </summary>
	Block64V512 = 1 << 9
}
