using CryptoBase.Abstractions;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.Macs.GHash;
using System.Security.Cryptography;

namespace CryptoBase.SymmetricCryptos.AEADCryptos.GCM;

public class GcmCryptoModeBlock16X86 : IAEADCrypto
{
	public string Name => _crypto16.Name + @"-GCM";

	public const int BlockSize = 16;
	public const int BlockSize16 = 16 * BlockSize;
	public const int NonceSize = 12;
	public const int TagSize = 16;

	private static ReadOnlySpan<byte> Init => new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	private static readonly Vector256<uint> VCounter1 = Vector256.Create(10u, 11, 12, 13, 14, 15, 16, 17);
	private static readonly Vector256<uint> VAdd8 = Vector256.Create(8u);

	private readonly IBlockCrypto _crypto;
	private readonly IBlockCrypto _crypto16;

	private readonly byte[] _buffer;
	private readonly byte[] _tagBuffer;
	private readonly byte[] _counterBlock;
	private readonly IMac _gHash;

	public GcmCryptoModeBlock16X86(IBlockCrypto crypto, IBlockCrypto crypto16)
	{
		if (crypto.BlockSize is not BlockSize)
		{
			throw new ArgumentException($@"Crypto block size must be {BlockSize} bytes.", nameof(crypto));
		}

		if (crypto16.BlockSize is not BlockSize16)
		{
			throw new ArgumentException($@"Crypto block size must be {BlockSize16} bytes.", nameof(crypto16));
		}

		_crypto = crypto;
		_crypto16 = crypto16;

		_buffer = ArrayPool<byte>.Shared.Rent(BlockSize16);
		_tagBuffer = ArrayPool<byte>.Shared.Rent(TagSize);
		_counterBlock = ArrayPool<byte>.Shared.Rent(BlockSize16);

		Span<byte> key = _buffer.AsSpan(0, 16);
		_crypto.Encrypt(Init, key);
		_gHash = GHashUtils.Create(key);
	}

	public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source,
		Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
	{
		CheckInput(nonce, source, destination);

		ulong length = (ulong)source.Length << 3;

		Span<byte> counterBlock = _counterBlock.AsSpan(0, BlockSize16);
		counterBlock.Clear();

		Span<byte> counter0 = counterBlock.Slice(12 + 0 * BlockSize, 4);
		Span<byte> counter1 = counterBlock.Slice(12 + 1 * BlockSize, 4);
		Span<byte> counter2 = counterBlock.Slice(12 + 2 * BlockSize, 4);
		Span<byte> counter3 = counterBlock.Slice(12 + 3 * BlockSize, 4);
		Span<byte> counter4 = counterBlock.Slice(12 + 4 * BlockSize, 4);
		Span<byte> counter5 = counterBlock.Slice(12 + 5 * BlockSize, 4);
		Span<byte> counter6 = counterBlock.Slice(12 + 6 * BlockSize, 4);
		Span<byte> counter7 = counterBlock.Slice(12 + 7 * BlockSize, 4);
		Span<byte> counter8 = counterBlock.Slice(12 + 8 * BlockSize, 4);
		Span<byte> counter9 = counterBlock.Slice(12 + 9 * BlockSize, 4);
		Span<byte> counter10 = counterBlock.Slice(12 + 10 * BlockSize, 4);
		Span<byte> counter11 = counterBlock.Slice(12 + 11 * BlockSize, 4);
		Span<byte> counter12 = counterBlock.Slice(12 + 12 * BlockSize, 4);
		Span<byte> counter13 = counterBlock.Slice(12 + 13 * BlockSize, 4);
		Span<byte> counter14 = counterBlock.Slice(12 + 14 * BlockSize, 4);
		Span<byte> counter15 = counterBlock.Slice(12 + 15 * BlockSize, 4);

		nonce.CopyTo(counterBlock);
		nonce.CopyTo(counterBlock[(1 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(2 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(3 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(4 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(5 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(6 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(7 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(8 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(9 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(10 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(11 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(12 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(13 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(14 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(15 * BlockSize)..]);

		counter0[3] = 1;
		counter1[3] = 3;
		counter2[3] = 4;
		counter3[3] = 5;
		counter4[3] = 6;
		counter5[3] = 7;
		counter6[3] = 8;
		counter7[3] = 9;
		counter8[3] = 10;
		counter9[3] = 11;
		counter10[3] = 12;
		counter11[3] = 13;
		counter12[3] = 14;
		counter13[3] = 15;
		counter14[3] = 16;
		counter15[3] = 17;

		_crypto.Encrypt(counterBlock[..BlockSize], tag);
		counter0[3] = 2;
		_gHash.Update(associatedData);

		Vector256<uint> v1 = VCounter1;

		while (!source.IsEmpty)
		{
			_crypto16.Encrypt(counterBlock, _buffer);

			Vector256<uint> v0 = Avx2.Add(v1, VAdd8);
			v1 = Avx2.Add(v0, VAdd8);

			BinaryPrimitives.WriteUInt32BigEndian(counter0, v0.GetElement(0));
			BinaryPrimitives.WriteUInt32BigEndian(counter1, v0.GetElement(1));
			BinaryPrimitives.WriteUInt32BigEndian(counter2, v0.GetElement(2));
			BinaryPrimitives.WriteUInt32BigEndian(counter3, v0.GetElement(3));
			BinaryPrimitives.WriteUInt32BigEndian(counter4, v0.GetElement(4));
			BinaryPrimitives.WriteUInt32BigEndian(counter5, v0.GetElement(5));
			BinaryPrimitives.WriteUInt32BigEndian(counter6, v0.GetElement(6));
			BinaryPrimitives.WriteUInt32BigEndian(counter7, v0.GetElement(7));
			BinaryPrimitives.WriteUInt32BigEndian(counter8, v1.GetElement(0));
			BinaryPrimitives.WriteUInt32BigEndian(counter9, v1.GetElement(1));
			BinaryPrimitives.WriteUInt32BigEndian(counter10, v1.GetElement(2));
			BinaryPrimitives.WriteUInt32BigEndian(counter11, v1.GetElement(3));
			BinaryPrimitives.WriteUInt32BigEndian(counter12, v1.GetElement(4));
			BinaryPrimitives.WriteUInt32BigEndian(counter13, v1.GetElement(5));
			BinaryPrimitives.WriteUInt32BigEndian(counter14, v1.GetElement(6));
			BinaryPrimitives.WriteUInt32BigEndian(counter15, v1.GetElement(7));

			int n = Math.Min(source.Length, BlockSize16);

			FastUtils.Xor(source, _buffer, destination, n);

			_gHash.Update(destination[..n]);

			source = source[n..];
			destination = destination[n..];
		}

		BinaryPrimitives.WriteUInt64BigEndian(_buffer, (ulong)associatedData.Length << 3);
		BinaryPrimitives.WriteUInt64BigEndian(_buffer.AsSpan(8), length);

		_gHash.Update(_buffer.AsSpan(0, TagSize));
		_gHash.GetMac(_buffer);

		FastUtils.Xor(tag, _buffer, tag, 16);
	}

	public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag,
		Span<byte> destination, ReadOnlySpan<byte> associatedData = default)
	{
		CheckInput(nonce, source, destination);

		ulong length = (ulong)source.Length << 3;

		Span<byte> counterBlock = _counterBlock.AsSpan(0, BlockSize16);
		counterBlock.Clear();

		Span<byte> counter0 = counterBlock.Slice(12 + 0 * BlockSize, 4);
		Span<byte> counter1 = counterBlock.Slice(12 + 1 * BlockSize, 4);
		Span<byte> counter2 = counterBlock.Slice(12 + 2 * BlockSize, 4);
		Span<byte> counter3 = counterBlock.Slice(12 + 3 * BlockSize, 4);
		Span<byte> counter4 = counterBlock.Slice(12 + 4 * BlockSize, 4);
		Span<byte> counter5 = counterBlock.Slice(12 + 5 * BlockSize, 4);
		Span<byte> counter6 = counterBlock.Slice(12 + 6 * BlockSize, 4);
		Span<byte> counter7 = counterBlock.Slice(12 + 7 * BlockSize, 4);
		Span<byte> counter8 = counterBlock.Slice(12 + 8 * BlockSize, 4);
		Span<byte> counter9 = counterBlock.Slice(12 + 9 * BlockSize, 4);
		Span<byte> counter10 = counterBlock.Slice(12 + 10 * BlockSize, 4);
		Span<byte> counter11 = counterBlock.Slice(12 + 11 * BlockSize, 4);
		Span<byte> counter12 = counterBlock.Slice(12 + 12 * BlockSize, 4);
		Span<byte> counter13 = counterBlock.Slice(12 + 13 * BlockSize, 4);
		Span<byte> counter14 = counterBlock.Slice(12 + 14 * BlockSize, 4);
		Span<byte> counter15 = counterBlock.Slice(12 + 15 * BlockSize, 4);

		nonce.CopyTo(counterBlock);
		nonce.CopyTo(counterBlock[(1 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(2 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(3 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(4 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(5 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(6 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(7 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(8 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(9 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(10 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(11 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(12 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(13 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(14 * BlockSize)..]);
		nonce.CopyTo(counterBlock[(15 * BlockSize)..]);

		counter0[3] = 1;
		counter1[3] = 3;
		counter2[3] = 4;
		counter3[3] = 5;
		counter4[3] = 6;
		counter5[3] = 7;
		counter6[3] = 8;
		counter7[3] = 9;
		counter8[3] = 10;
		counter9[3] = 11;
		counter10[3] = 12;
		counter11[3] = 13;
		counter12[3] = 14;
		counter13[3] = 15;
		counter14[3] = 16;
		counter15[3] = 17;

		_crypto.Encrypt(counterBlock, _tagBuffer);
		counter0[3] = 2;
		_gHash.Update(associatedData);

		Vector256<uint> v1 = VCounter1;

		while (!source.IsEmpty)
		{
			_crypto16.Encrypt(counterBlock, _buffer);

			Vector256<uint> v0 = Avx2.Add(v1, VAdd8);
			v1 = Avx2.Add(v0, VAdd8);

			BinaryPrimitives.WriteUInt32BigEndian(counter0, v0.GetElement(0));
			BinaryPrimitives.WriteUInt32BigEndian(counter1, v0.GetElement(1));
			BinaryPrimitives.WriteUInt32BigEndian(counter2, v0.GetElement(2));
			BinaryPrimitives.WriteUInt32BigEndian(counter3, v0.GetElement(3));
			BinaryPrimitives.WriteUInt32BigEndian(counter4, v0.GetElement(4));
			BinaryPrimitives.WriteUInt32BigEndian(counter5, v0.GetElement(5));
			BinaryPrimitives.WriteUInt32BigEndian(counter6, v0.GetElement(6));
			BinaryPrimitives.WriteUInt32BigEndian(counter7, v0.GetElement(7));
			BinaryPrimitives.WriteUInt32BigEndian(counter8, v1.GetElement(0));
			BinaryPrimitives.WriteUInt32BigEndian(counter9, v1.GetElement(1));
			BinaryPrimitives.WriteUInt32BigEndian(counter10, v1.GetElement(2));
			BinaryPrimitives.WriteUInt32BigEndian(counter11, v1.GetElement(3));
			BinaryPrimitives.WriteUInt32BigEndian(counter12, v1.GetElement(4));
			BinaryPrimitives.WriteUInt32BigEndian(counter13, v1.GetElement(5));
			BinaryPrimitives.WriteUInt32BigEndian(counter14, v1.GetElement(6));
			BinaryPrimitives.WriteUInt32BigEndian(counter15, v1.GetElement(7));

			int n = Math.Min(source.Length, BlockSize16);

			_gHash.Update(source[..n]);

			FastUtils.Xor(source, _buffer, destination, n);

			source = source[n..];
			destination = destination[n..];
		}

		BinaryPrimitives.WriteUInt64BigEndian(_buffer, (ulong)associatedData.Length << 3);
		BinaryPrimitives.WriteUInt64BigEndian(_buffer.AsSpan(8), length);

		_gHash.Update(_buffer.AsSpan(0, TagSize));
		_gHash.GetMac(_buffer);

		FastUtils.Xor(_tagBuffer, _buffer, _tagBuffer, 16);

		if (!CryptographicOperations.FixedTimeEquals(_tagBuffer.AsSpan(0, TagSize), tag))
		{
			throw new ArgumentException(@"Unable to decrypt input with these parameters.");
		}
	}

	private static void CheckInput(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> destination)
	{
		if (nonce.Length is not NonceSize)
		{
			throw new ArgumentException(@"Nonce size must be 12 bytes", nameof(nonce));
		}

		if (destination.Length != source.Length)
		{
			throw new ArgumentException(@"Plaintext and ciphertext must have the same length.", nameof(destination));
		}
	}

	public void Dispose()
	{
		_crypto.Dispose();
		_crypto16.Dispose();
		_gHash.Dispose();

		ArrayPool<byte>.Shared.Return(_buffer);
		ArrayPool<byte>.Shared.Return(_tagBuffer);
		ArrayPool<byte>.Shared.Return(_counterBlock);

		GC.SuppressFinalize(this);
	}
}
