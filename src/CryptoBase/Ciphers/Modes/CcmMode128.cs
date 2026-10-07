using CryptoBase.Ciphers.Modes.Ccm;

namespace CryptoBase.Ciphers.Modes;

/// <summary>
/// Provides Counter with CBC-MAC authenticated encryption for a 16-byte block cipher.
/// </summary>
/// <remarks>Each message is limited to 2^24 - 1 bytes.</remarks>
/// <typeparam name="TBlockCipher">The block cipher type.</typeparam>
public sealed class CcmMode128<TBlockCipher> : IAeadCipher<CcmMode128<TBlockCipher>> where TBlockCipher : IBlockEncryptor<TBlockCipher>
{
	/// <inheritdoc />
	public static CcmMode128<TBlockCipher> Create(scoped ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(TBlockCipher.BlockSize, 16);
		return new CcmMode128<TBlockCipher>(TBlockCipher.Create(key));
	}

	/// <inheritdoc />
	public static int NonceSize => CcmUtils.NonceSize;

	/// <inheritdoc />
	public static int TagSize => CcmTag16.Size;

	private readonly TBlockCipher _blockCipher;

	private CcmMode128(TBlockCipher blockCipher)
	{
		_blockCipher = blockCipher;
	}

	/// <inheritdoc/>
	public void Encrypt(scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination, scoped Span<byte> tag, scoped ReadOnlySpan<byte> associatedData = default)
	{
		CcmModeCore<TBlockCipher, CcmTag16>.Encrypt(_blockCipher, nonce, source, destination, tag, associatedData);
	}

	/// <inheritdoc/>
	public bool TryDecrypt(scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> source, scoped ReadOnlySpan<byte> tag, scoped Span<byte> destination, scoped ReadOnlySpan<byte> associatedData = default)
	{
		return CcmModeCore<TBlockCipher, CcmTag16>.TryDecrypt(_blockCipher, nonce, source, tag, destination, associatedData);
	}

	/// <inheritdoc/>
	public void Dispose()
	{
		_blockCipher.Dispose();
	}
}
