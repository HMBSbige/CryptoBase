namespace CryptoBase.Abstractions.Ciphers;

/// <summary>
/// Defines data-unit encryption and decryption.
/// </summary>
/// <remarks>Each operation writes exactly as many bytes as the source holds to the start of the destination.</remarks>
public interface IDataUnitCipher<out TSelf> : IDisposable where TSelf : IDataUnitCipher<TSelf>, allows ref struct
{
	/// <summary>
	/// Gets the tweak size, in bytes.
	/// </summary>
	static abstract int TweakSize { get; }

	/// <summary>
	/// Creates an instance initialized with <paramref name="key" />.
	/// </summary>
	static abstract TSelf Create(scoped ReadOnlySpan<byte> key);

	/// <summary>
	/// Encrypts the data unit in <paramref name="source" /> into <paramref name="destination" />.
	/// </summary>
	/// <remarks>The tweak must be <see cref="TweakSize" /> bytes long and the destination at least as long as the source. If source and destination overlap, they must start at the same byte.</remarks>
	void Encrypt(scoped ReadOnlySpan<byte> tweak, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination);

	/// <summary>
	/// Decrypts the data unit in <paramref name="source" /> into <paramref name="destination" />.
	/// </summary>
	/// <remarks>The tweak must be <see cref="TweakSize" /> bytes long and the destination at least as long as the source. If source and destination overlap, they must start at the same byte.</remarks>
	void Decrypt(scoped ReadOnlySpan<byte> tweak, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination);
}
