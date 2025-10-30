namespace CryptoBase.Abstractions.SymmetricCryptos;

public abstract class SnuffleCryptoBase : StreamCryptoBase
{
	public const int StateSize = 16; // 64 bytes

	public const int BlockSize = StateSize * sizeof(uint);

	public virtual int IvSize => 8;
}
