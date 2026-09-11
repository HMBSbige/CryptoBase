namespace CryptoBase.Abstractions.Ciphers;

/// <summary>
/// Defines a block cipher.
/// </summary>
public interface IBlockCipher<out TSelf> : IBlockEncryptor<TSelf> where TSelf : IBlockCipher<TSelf>, allows ref struct
{
	/// <summary>
	/// Decrypts <paramref name="source" /> into <paramref name="destination" />; source must be exactly one block.
	/// </summary>
	/// <remarks>If source and destination overlap, they must start at the same byte.</remarks>
	void DecryptBlock(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination);

	/// <summary>
	/// Decrypts <paramref name="source" /> into <paramref name="destination" />; source length must be a multiple of the block size.
	/// </summary>
	/// <remarks>If source and destination overlap, they must start at the same byte.</remarks>
	void DecryptBlocks(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination);
}
