namespace CryptoBase.Abstractions.SymmetricCryptos;

/// <summary>
/// Provides a base class for Salsa- and ChaCha-family stream ciphers.
/// </summary>
public abstract class SnuffleCryptoBase : StreamCryptoBase
{
	/// <summary>
	/// The number of 32-bit words in the cipher state.
	/// </summary>
	public const int StateSize = 16; // 64 bytes

	/// <summary>
	/// The block size, in bytes.
	/// </summary>
	public const int BlockSize = StateSize * sizeof(uint);

	/// <summary>
	/// Gets the initialization vector size, in bytes.
	/// </summary>
	public virtual int IVSize => 8;
}
