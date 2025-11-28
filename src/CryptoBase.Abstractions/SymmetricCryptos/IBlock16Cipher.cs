namespace CryptoBase.Abstractions.SymmetricCryptos;

public interface IBlock16Cipher<out TSelf> : IDisposable where TSelf : IBlock16Cipher<TSelf>
{
	static abstract bool IsSupported { get; }

	static abstract TSelf Create(in ReadOnlySpan<byte> key);

	VectorBuffer16 Encrypt(scoped in VectorBuffer16 source);

	VectorBuffer16 Decrypt(scoped in VectorBuffer16 source);
}
