using CryptoBase.SymmetricCryptos.BlockCryptoModes.Gcm;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

/// <summary>
/// Provides Galois/Counter Mode authenticated encryption for a 16-byte block cipher.
/// </summary>
/// <typeparam name="TBlockCipher">The block cipher type.</typeparam>
public sealed class GcmMode128<TBlockCipher> : IAeadCrypto where TBlockCipher : IBlock16Cipher<TBlockCipher>
{
	/// <inheritdoc/>
	public string Name => _blockCipher.Name + @"-GCM";

	/// <inheritdoc />
	public int NonceSizeInBytes => NonceSize;

	/// <inheritdoc />
	public int TagSizeInBytes => TagSize;

	/// <summary>The block size, in bytes.</summary>
	public const int BlockSize = 16;
	/// <summary>The required nonce size, in bytes.</summary>
	public const int NonceSize = 12;
	/// <summary>The authentication tag size, in bytes.</summary>
	public const int TagSize = 16;

	private readonly TBlockCipher _blockCipher;
	private readonly bool _disposeCrypto;
	private GHash _gHash;
	private readonly CtrMode128Ctr32<TBlockCipher> _ctr;

	/// <summary>
	/// Initializes a GCM instance.
	/// </summary>
	/// <param name="blockCipher">The block cipher.</param>
	/// <param name="disposeCrypto">Whether to dispose <paramref name="blockCipher"/> with this instance.</param>
	public GcmMode128(TBlockCipher blockCipher, bool disposeCrypto = true)
	{
		_blockCipher = blockCipher;
		_disposeCrypto = disposeCrypto;

		VectorBuffer16 buffer16 = default;
		buffer16 = blockCipher.Encrypt(buffer16);
		_gHash = GHash.Create(buffer16);

		_ctr = new CtrMode128Ctr32<TBlockCipher>(blockCipher, default, false);
	}

	/// <inheritdoc/>
	[SkipLocalsInit]
	public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
	{
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, NonceSize, TagSize);
		bool associatedDataOverlapsDestination = associatedData.Overlaps(destination);

		Unsafe.SkipInit(out VectorBuffer16 buffer16);
		Span<byte> buffer = buffer16.AsSpan();
		nonce.CopyTo(buffer);
		BinaryPrimitives.WriteUInt32BigEndian(buffer.Slice(12), 1);

		VectorBuffer16 tagBuffer = _blockCipher.Encrypt(buffer16);
		if (associatedDataOverlapsDestination)
		{
			_gHash.AppendPaddedSegment(associatedData);
		}

		buffer[15] = 2;
		_ctr.SetIV(buffer);

		_ctr.Update(source, destination);

		BinaryPrimitives.WriteUInt64BigEndian(buffer, (ulong)associatedData.Length << 3);
		BinaryPrimitives.WriteUInt64BigEndian(buffer.Slice(8), (ulong)source.Length << 3);

		_gHash.HashPaddedSegmentsAndReset(associatedDataOverlapsDestination ? ReadOnlySpan<byte>.Empty : associatedData, destination, buffer, buffer);

		tagBuffer ^= buffer16;
		MemoryMarshal.Write(tag, in tagBuffer);
	}

	/// <inheritdoc/>
	[SkipLocalsInit]
	public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData = default)
	{
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, NonceSize, TagSize);

		Unsafe.SkipInit(out VectorBuffer16 buffer16);
		Span<byte> buffer = buffer16.AsSpan();
		nonce.CopyTo(buffer);
		BinaryPrimitives.WriteUInt32BigEndian(buffer.Slice(12), 1);

		VectorBuffer16 tagBuffer = _blockCipher.Encrypt(buffer16);

		buffer[15] = 2;
		_ctr.SetIV(buffer);

		BinaryPrimitives.WriteUInt64BigEndian(buffer, (ulong)associatedData.Length << 3);
		BinaryPrimitives.WriteUInt64BigEndian(buffer.Slice(8), (ulong)source.Length << 3);

		_gHash.HashPaddedSegmentsAndReset(associatedData, source, buffer, buffer);

		tagBuffer ^= buffer16;

		ThrowHelper.ThrowIfAuthenticationTagMismatch(tagBuffer, tag);
		_ctr.Update(source, destination);
	}

	/// <inheritdoc/>
	public void Dispose()
	{
		_ctr.Dispose();
		_gHash.ZeroMemory();

		if (_disposeCrypto)
		{
			_blockCipher.Dispose();
		}
	}
}
