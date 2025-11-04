using CryptoBase.Abstractions;
using CryptoBase.Macs.GHash;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public class GcmMode128 : IAEADCrypto
{
	public string Name => _crypto.Name + @"-GCM";

	public const int BlockSize = 16;
	public const int NonceSize = 12;
	public const int TagSize = 16;

	private static ReadOnlySpan<byte> Init => "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"u8;

	private readonly bool _disposeCrypto;
	private readonly IBlockCrypto _crypto;
	private readonly IMac _gHash;

	public GcmMode128(IBlockCrypto crypto, bool disposeCrypto = true)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(crypto.BlockSize, BlockSize, nameof(crypto));
		_crypto = crypto;
		_disposeCrypto = disposeCrypto;

		Span<byte> buffer = stackalloc byte[BlockSize];
		crypto.Encrypt(Init, buffer);
		_gHash = GHashUtils.Create(buffer);
	}

	[SkipLocalsInit]
	public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
	{
		CheckInput(nonce, source, destination);

		Span<byte> buffer = stackalloc byte[BlockSize];
		nonce.CopyTo(buffer);
		buffer[12] = 0;
		buffer[13] = 0;
		buffer[14] = 0;
		buffer[15] = 1;

		_crypto.Encrypt(buffer, tag);
		_gHash.Update(associatedData);

		buffer[15] = 2;
		using CtrMode128 ctr = new(_crypto, buffer, false);

		ctr.Update(source, destination);
		_gHash.Update(destination);

		BinaryPrimitives.WriteUInt64BigEndian(buffer, (ulong)associatedData.Length << 3);
		BinaryPrimitives.WriteUInt64BigEndian(buffer.Slice(8), (ulong)source.Length << 3);

		_gHash.Update(buffer.Slice(0, TagSize));
		_gHash.GetMac(buffer);

		FastUtils.Xor16(tag, buffer);
	}

	[SkipLocalsInit]
	public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData = default)
	{
		CheckInput(nonce, source, destination);

		Span<byte> tagBuffer = stackalloc byte[TagSize];
		Span<byte> buffer = stackalloc byte[BlockSize];
		nonce.CopyTo(buffer);
		buffer[12] = 0;
		buffer[13] = 0;
		buffer[14] = 0;
		buffer[15] = 1;

		_crypto.Encrypt(buffer, tagBuffer);
		_gHash.Update(associatedData);

		buffer[15] = 2;
		using CtrMode128 ctr = new(_crypto, buffer, false);

		ctr.Update(source, destination);
		_gHash.Update(source);

		BinaryPrimitives.WriteUInt64BigEndian(buffer, (ulong)associatedData.Length << 3);
		BinaryPrimitives.WriteUInt64BigEndian(buffer.Slice(8), (ulong)source.Length << 3);

		_gHash.Update(buffer.Slice(0, TagSize));
		_gHash.GetMac(buffer);

		FastUtils.Xor16(tagBuffer, buffer);

		ThrowHelper.ThrowIfAuthenticationTagMismatch(tagBuffer, tag);
	}

	private static void CheckInput(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(nonce.Length, NonceSize, nameof(nonce));

		ArgumentOutOfRangeException.ThrowIfNotEqual(destination.Length, source.Length, nameof(destination));
	}

	public void Dispose()
	{
		if (_disposeCrypto)
		{
			_crypto.Dispose();
		}

		_gHash.Dispose();

		GC.SuppressFinalize(this);
	}
}
