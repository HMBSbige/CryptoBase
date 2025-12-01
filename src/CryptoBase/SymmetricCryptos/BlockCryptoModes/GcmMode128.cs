using CryptoBase.Macs.GHash;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public class GcmMode128<TBlockCipher> : IAEADCrypto where TBlockCipher : IBlock16Cipher<TBlockCipher>
{
	public string Name => _blockCipher.Name + @"-GCM";

	public const int BlockSize = 16;
	public const int NonceSize = 12;
	public const int TagSize = 16;

	private readonly TBlockCipher _blockCipher;
	private readonly bool _disposeCrypto;
	private readonly IMac _gHash;

	public GcmMode128(TBlockCipher blockCipher, bool disposeCrypto = true)
	{
		_blockCipher = blockCipher;
		_disposeCrypto = disposeCrypto;

		VectorBuffer16 buffer16 = default;
		buffer16 = blockCipher.Encrypt(buffer16);
		_gHash = GHashUtils.Create(buffer16);
	}

	[SkipLocalsInit]
	public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
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
		using CtrMode128Ctr32<TBlockCipher> ctr = new(_blockCipher, buffer, false);

		ctr.Update(source, destination);
		_gHash.Update(destination);

		BinaryPrimitives.WriteUInt64BigEndian(buffer, (ulong)associatedData.Length << 3);
		BinaryPrimitives.WriteUInt64BigEndian(buffer.Slice(8), (ulong)source.Length << 3);

		_gHash.Update(buffer.Slice(0, TagSize));
		_gHash.GetMac(buffer);

		tagBuffer ^= buffer16;
		Unsafe.WriteUnaligned(ref tag.GetReference(), tagBuffer);
	}

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
		using CtrMode128Ctr32<TBlockCipher> ctr = new(_blockCipher, buffer, false);

		ctr.Update(source, destination);
		_gHash.Update(source);

		BinaryPrimitives.WriteUInt64BigEndian(buffer, (ulong)associatedData.Length << 3);
		BinaryPrimitives.WriteUInt64BigEndian(buffer.Slice(8), (ulong)source.Length << 3);

		_gHash.Update(buffer.Slice(0, TagSize));
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

	public void Dispose()
	{
		if (_disposeCrypto)
		{
			_blockCipher.Dispose();
		}

		_gHash.Dispose();

		GC.SuppressFinalize(this);
	}
}
