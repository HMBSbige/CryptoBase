using CryptoBase.Macs.GHash;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

/// <summary>
/// Provides Galois/Counter Mode authenticated encryption for a 16-byte block cipher.
/// </summary>
/// <typeparam name="TBlockCipher">The block cipher type.</typeparam>
public sealed class GcmMode128<TBlockCipher> : IAEADCrypto where TBlockCipher : IBlock16Cipher<TBlockCipher>
{
	/// <inheritdoc/>
	public string Name => _blockCipher.Name + @"-GCM";

	/// <summary>The block size, in bytes.</summary>
	public const int BlockSize = 16;
	/// <summary>The required nonce size, in bytes.</summary>
	public const int NonceSize = 12;
	/// <summary>The authentication tag size, in bytes.</summary>
	public const int TagSize = 16;

	private readonly TBlockCipher _blockCipher;
	private readonly bool _disposeCrypto;
	private readonly IMac _gHash;
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
		_gHash = GHashUtils.Create(buffer16);

		_ctr = new CtrMode128Ctr32<TBlockCipher>(blockCipher, default, false);
	}

	/// <inheritdoc/>
	[SkipLocalsInit]
	public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
	{
		CheckInput(nonce, source, destination);
		ArgumentOutOfRangeException.ThrowIfLessThan(tag.Length, TagSize, nameof(tag));

		Unsafe.SkipInit(out VectorBuffer16 buffer16);
		Span<byte> buffer = buffer16.AsSpan();
		nonce.CopyTo(buffer);
		buffer[12] = 0;
		buffer[13] = 0;
		buffer[14] = 0;
		buffer[15] = 1;

		VectorBuffer16 tagBuffer = _blockCipher.Encrypt(buffer16);
		_gHash.Update(associatedData);

		buffer[15] = 2;
		_ctr.SetIv(buffer);

		_ctr.Update(source, destination);
		_gHash.Update(destination);

		BinaryPrimitives.WriteUInt64BigEndian(buffer, (ulong)associatedData.Length << 3);
		BinaryPrimitives.WriteUInt64BigEndian(buffer.Slice(8), (ulong)source.Length << 3);

		_gHash.Update(buffer);
		_gHash.GetMac(buffer);

		tagBuffer ^= buffer16;
		Unsafe.WriteUnaligned(ref tag.GetReference(), tagBuffer);
	}

	/// <inheritdoc/>
	[SkipLocalsInit]
	public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData = default)
	{
		CheckInput(nonce, source, destination);

		Unsafe.SkipInit(out VectorBuffer16 buffer16);
		Span<byte> buffer = buffer16.AsSpan();
		nonce.CopyTo(buffer);
		buffer[12] = 0;
		buffer[13] = 0;
		buffer[14] = 0;
		buffer[15] = 1;

		VectorBuffer16 tagBuffer = _blockCipher.Encrypt(buffer16);
		_gHash.Update(associatedData);

		buffer[15] = 2;
		_ctr.SetIv(buffer);

		_ctr.Update(source, destination);
		_gHash.Update(source);

		BinaryPrimitives.WriteUInt64BigEndian(buffer, (ulong)associatedData.Length << 3);
		BinaryPrimitives.WriteUInt64BigEndian(buffer.Slice(8), (ulong)source.Length << 3);

		_gHash.Update(buffer);
		_gHash.GetMac(buffer);

		tagBuffer ^= buffer16;

		ThrowHelper.ThrowIfAuthenticationTagMismatch(tagBuffer, tag);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void CheckInput(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(nonce.Length, NonceSize, nameof(nonce));

		ArgumentOutOfRangeException.ThrowIfNotEqual(destination.Length, source.Length, nameof(destination));
	}

	/// <inheritdoc/>
	public void Dispose()
	{
		_ctr.Dispose();
		_gHash.Dispose();

		if (_disposeCrypto)
		{
			_blockCipher.Dispose();
		}
	}
}
