namespace CryptoBase.Abstractions.Ciphers;

/// <summary>
/// Defines block encryption operations.
/// </summary>
public interface IBlockEncryptor<out TSelf> : IDisposable where TSelf : IBlockEncryptor<TSelf>, allows ref struct
{
	/// <summary>
	/// Gets the block size, in bytes.
	/// </summary>
	static abstract int BlockSizeInBytes { get; }

	/// <summary>
	/// Creates an instance initialized with <paramref name="key" />.
	/// </summary>
	static abstract TSelf Create(scoped ReadOnlySpan<byte> key);

	/// <summary>
	/// Encrypts <paramref name="source" /> into <paramref name="destination" />; source must be exactly one block.
	/// </summary>
	/// <remarks>If source and destination overlap, they must start at the same byte.</remarks>
	void EncryptBlock(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination);

	/// <summary>
	/// Encrypts <paramref name="source" /> into <paramref name="destination" />; source length must be a multiple of the block size.
	/// </summary>
	/// <remarks>If source and destination overlap, they must start at the same byte.</remarks>
	void EncryptBlocks(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination);
}
