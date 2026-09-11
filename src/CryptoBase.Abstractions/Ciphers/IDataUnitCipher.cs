namespace CryptoBase.Abstractions.Ciphers;

/// <summary>
/// Defines data-unit encryption and decryption.
/// </summary>
public interface IDataUnitCipher<out TSelf> : IDisposable where TSelf : IDataUnitCipher<TSelf>, allows ref struct
{
	/// <summary>
	/// Gets the tweak size, in bytes.
	/// </summary>
	static abstract int TweakSizeInBytes { get; }

	/// <summary>
	/// Creates an instance initialized with <paramref name="key" />.
	/// </summary>
	static abstract TSelf Create(scoped ReadOnlySpan<byte> key);

	/// <summary>
	/// Encrypts the data unit in <paramref name="source" /> into <paramref name="destination" />.
	/// </summary>
	void Encrypt(scoped ReadOnlySpan<byte> tweak, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination);

	/// <summary>
	/// Decrypts the data unit in <paramref name="source" /> into <paramref name="destination" />.
	/// </summary>
	void Decrypt(scoped ReadOnlySpan<byte> tweak, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination);
}
