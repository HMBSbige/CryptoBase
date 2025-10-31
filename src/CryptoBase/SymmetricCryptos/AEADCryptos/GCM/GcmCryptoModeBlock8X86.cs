using CryptoBase.Abstractions;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.Macs.GHash;

namespace CryptoBase.SymmetricCryptos.AEADCryptos.GCM;

public class GcmCryptoModeBlock8X86 : IAEADCrypto
{
	public string Name => _crypto.Name + @"-GCM";

	public const int BlockSize = 16;
	public const int BlockSize8 = 8 * BlockSize;
	public const int NonceSize = 12;
	public const int TagSize = 16;

	private static ReadOnlySpan<byte> Init => "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"u8;

	private readonly IBlockCrypto _crypto;

	private readonly byte[] _buffer;
	private readonly byte[] _tagBuffer;
	private readonly byte[] _counterBlock;
	private readonly IMac _gHash;

	public GcmCryptoModeBlock8X86(IBlockCrypto crypto)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(crypto.BlockSize, BlockSize, nameof(crypto));

		_crypto = crypto;

		_buffer = ArrayPool<byte>.Shared.Rent(BlockSize8);
		_tagBuffer = ArrayPool<byte>.Shared.Rent(TagSize);
		_counterBlock = ArrayPool<byte>.Shared.Rent(BlockSize8);

		Span<byte> key = _buffer.AsSpan(0, 16);
		_crypto.Encrypt(Init, key);
		_gHash = GHashUtils.Create(key);
	}

	public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source,
		Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
	{
		CheckInput(nonce, source, destination);

		ulong length = (ulong)source.Length << 3;

		Span<byte> counterBlock = _counterBlock.AsSpan(0, BlockSize8);
		counterBlock.Clear();

		Span<byte> counter0 = counterBlock.Slice(12 + 0 * BlockSize, 4);
		Span<byte> counter1 = counterBlock.Slice(12 + 1 * BlockSize, 4);
		Span<byte> counter2 = counterBlock.Slice(12 + 2 * BlockSize, 4);
		Span<byte> counter3 = counterBlock.Slice(12 + 3 * BlockSize, 4);
		Span<byte> counter4 = counterBlock.Slice(12 + 4 * BlockSize, 4);
		Span<byte> counter5 = counterBlock.Slice(12 + 5 * BlockSize, 4);
		Span<byte> counter6 = counterBlock.Slice(12 + 6 * BlockSize, 4);
		Span<byte> counter7 = counterBlock.Slice(12 + 7 * BlockSize, 4);

		nonce.CopyTo(counterBlock);
		nonce.CopyTo(counterBlock[(1 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(2 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(3 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(4 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(5 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(6 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(7 * BlockSize)..]);

		counter0[3] = 1;
		counter1[3] = 3;
		counter2[3] = 4;
		counter3[3] = 5;
		counter4[3] = 6;
		counter5[3] = 7;
		counter6[3] = 8;
		counter7[3] = 9;

		_crypto.Encrypt(counterBlock[..BlockSize], tag);
		counter0[3] = 2;
		_gHash.Update(associatedData);

		Vector128<uint> v1 = Vector128.Create(6u, 7, 8, 9);
		Vector128<uint> vAdd4 = Vector128.Create(4u);

		while (!source.IsEmpty)
		{
			_crypto.Encrypt8(counterBlock, _buffer);

			Vector128<uint> v0 = Sse2.Add(v1, vAdd4);
			v1 = Sse2.Add(v0, vAdd4);

			BinaryPrimitives.WriteUInt32BigEndian(counter0, v0.GetElement(0));
			BinaryPrimitives.WriteUInt32BigEndian(counter1, v0.GetElement(1));
			BinaryPrimitives.WriteUInt32BigEndian(counter2, v0.GetElement(2));
			BinaryPrimitives.WriteUInt32BigEndian(counter3, v0.GetElement(3));
			BinaryPrimitives.WriteUInt32BigEndian(counter4, v1.GetElement(0));
			BinaryPrimitives.WriteUInt32BigEndian(counter5, v1.GetElement(1));
			BinaryPrimitives.WriteUInt32BigEndian(counter6, v1.GetElement(2));
			BinaryPrimitives.WriteUInt32BigEndian(counter7, v1.GetElement(3));

			int n = Math.Min(source.Length, BlockSize8);

			FastUtils.Xor(source, _buffer, destination, n);

			_gHash.Update(destination[..n]);

			source = source[n..];
			destination = destination[n..];
		}

		BinaryPrimitives.WriteUInt64BigEndian(_buffer, (ulong)associatedData.Length << 3);
		BinaryPrimitives.WriteUInt64BigEndian(_buffer.AsSpan(8), length);

		_gHash.Update(_buffer.AsSpan(0, TagSize));
		_gHash.GetMac(_buffer);

		FastUtils.Xor16(tag, _buffer);
	}

	public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag,
		Span<byte> destination, ReadOnlySpan<byte> associatedData = default)
	{
		CheckInput(nonce, source, destination);

		ulong length = (ulong)source.Length << 3;

		Span<byte> counterBlock = _counterBlock.AsSpan(0, BlockSize8);
		counterBlock.Clear();

		Span<byte> counter0 = counterBlock.Slice(12 + 0 * BlockSize, 4);
		Span<byte> counter1 = counterBlock.Slice(12 + 1 * BlockSize, 4);
		Span<byte> counter2 = counterBlock.Slice(12 + 2 * BlockSize, 4);
		Span<byte> counter3 = counterBlock.Slice(12 + 3 * BlockSize, 4);
		Span<byte> counter4 = counterBlock.Slice(12 + 4 * BlockSize, 4);
		Span<byte> counter5 = counterBlock.Slice(12 + 5 * BlockSize, 4);
		Span<byte> counter6 = counterBlock.Slice(12 + 6 * BlockSize, 4);
		Span<byte> counter7 = counterBlock.Slice(12 + 7 * BlockSize, 4);

		nonce.CopyTo(counterBlock);
		nonce.CopyTo(counterBlock[(1 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(2 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(3 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(4 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(5 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(6 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(7 * BlockSize)..]);

		counter0[3] = 1;
		counter1[3] = 3;
		counter2[3] = 4;
		counter3[3] = 5;
		counter4[3] = 6;
		counter5[3] = 7;
		counter6[3] = 8;
		counter7[3] = 9;

		_crypto.Encrypt(counterBlock, _tagBuffer);
		counter0[3] = 2;
		_gHash.Update(associatedData);

		Vector128<uint> v1 = Vector128.Create(6u, 7, 8, 9);
		Vector128<uint> vAdd4 = Vector128.Create(4u);

		while (!source.IsEmpty)
		{
			_crypto.Encrypt8(counterBlock, _buffer);

			Vector128<uint> v0 = Sse2.Add(v1, vAdd4);
			v1 = Sse2.Add(v0, vAdd4);

			BinaryPrimitives.WriteUInt32BigEndian(counter0, v0.GetElement(0));
			BinaryPrimitives.WriteUInt32BigEndian(counter1, v0.GetElement(1));
			BinaryPrimitives.WriteUInt32BigEndian(counter2, v0.GetElement(2));
			BinaryPrimitives.WriteUInt32BigEndian(counter3, v0.GetElement(3));
			BinaryPrimitives.WriteUInt32BigEndian(counter4, v1.GetElement(0));
			BinaryPrimitives.WriteUInt32BigEndian(counter5, v1.GetElement(1));
			BinaryPrimitives.WriteUInt32BigEndian(counter6, v1.GetElement(2));
			BinaryPrimitives.WriteUInt32BigEndian(counter7, v1.GetElement(3));

			int n = Math.Min(source.Length, BlockSize8);

			_gHash.Update(source[..n]);

			FastUtils.Xor(source, _buffer, destination, n);

			source = source[n..];
			destination = destination[n..];
		}

		BinaryPrimitives.WriteUInt64BigEndian(_buffer, (ulong)associatedData.Length << 3);
		BinaryPrimitives.WriteUInt64BigEndian(_buffer.AsSpan(8), length);

		_gHash.Update(_buffer.AsSpan(0, TagSize));
		_gHash.GetMac(_buffer);

		FastUtils.Xor16(_tagBuffer, _buffer);

		ThrowHelper.ThrowIfAuthenticationTagMismatch(_tagBuffer.AsSpan(0, TagSize), tag);
	}

	private static void CheckInput(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(nonce.Length, NonceSize, nameof(nonce));

		ArgumentOutOfRangeException.ThrowIfNotEqual(destination.Length, source.Length, nameof(destination));
	}

	public void Dispose()
	{
		_crypto.Dispose();
		_gHash.Dispose();

		ArrayPool<byte>.Shared.Return(_buffer);
		ArrayPool<byte>.Shared.Return(_tagBuffer);
		ArrayPool<byte>.Shared.Return(_counterBlock);

		GC.SuppressFinalize(this);
	}
}
