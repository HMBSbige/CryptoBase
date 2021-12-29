using CryptoBase.Abstractions;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.Macs.GHash;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CryptoBase.SymmetricCryptos.AEADCryptos.GCM;

public class GcmCryptoMode : IAEADCrypto
{
	public string Name => _crypto.Name + @"-GCM";

	public const int BlockSize = 16;
	private const int BlockSize4 = BlockSize * 4;
	public const int NonceSize = 12;
	public const int TagSize = 16;

	private static ReadOnlySpan<byte> Init => new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	private readonly IBlockCrypto _crypto;

	private readonly byte[] _buffer;
	private readonly byte[] _tagBuffer;
	private readonly byte[] _counterBlock;
	private readonly IMac _gHash;

	public GcmCryptoMode(IBlockCrypto crypto)
	{
		if (crypto.BlockSize != BlockSize)
		{
			throw new ArgumentException(@"Crypto block size must be 16 bytes.", nameof(crypto));
		}
		_crypto = crypto;

		_buffer = ArrayPool<byte>.Shared.Rent(BlockSize4);
		_tagBuffer = ArrayPool<byte>.Shared.Rent(TagSize);
		_counterBlock = ArrayPool<byte>.Shared.Rent(BlockSize4);

		_crypto.Encrypt(Init, _buffer);
		_gHash = GHashUtils.Create(_buffer);
	}

	public unsafe void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source,
		Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
	{
		if (nonce.Length != NonceSize)
		{
			throw new ArgumentException(@"Nonce size must be 12 bytes", nameof(nonce));
		}

		if (destination.Length != source.Length)
		{
			throw new ArgumentException(@"Plaintext and ciphertext must have the same length.", nameof(destination));
		}

		var length = (ulong)source.Length << 3;

		var counterBlock = _counterBlock.AsSpan(0, BlockSize4);
		var counter0 = counterBlock.Slice(12, 4);
		var counter1 = counterBlock.Slice(28, 4);
		var counter2 = counterBlock.Slice(44, 4);
		var counter3 = counterBlock.Slice(60, 4);

		nonce.CopyTo(counterBlock);
		nonce.CopyTo(counterBlock[16..]);
		nonce.CopyTo(counterBlock[32..]);
		nonce.CopyTo(counterBlock[48..]);

		counter0[0] = 0;
		counter0[1] = 0;
		counter0[2] = 0;
		counter0[3] = 1;

		counter1[0] = 0;
		counter1[1] = 0;
		counter1[2] = 0;
		counter1[3] = 3;

		counter2[0] = 0;
		counter2[1] = 0;
		counter2[2] = 0;
		counter2[3] = 4;

		counter3[0] = 0;
		counter3[1] = 0;
		counter3[2] = 0;
		counter3[3] = 5;

		_crypto.Encrypt(counterBlock, tag);
		counter0[3] = 2;

		uint c3 = 5;

		_gHash.Update(associatedData);

		while (!source.IsEmpty)
		{
			_crypto.Encrypt4(counterBlock, _buffer);
			var c0 = c3 + 1;
			var c1 = c0 + 1;
			var c2 = c1 + 1;
			c3 = c2 + 1;
			BinaryPrimitives.WriteUInt32BigEndian(counter0, c0);
			BinaryPrimitives.WriteUInt32BigEndian(counter1, c1);
			BinaryPrimitives.WriteUInt32BigEndian(counter2, c2);
			BinaryPrimitives.WriteUInt32BigEndian(counter3, c3);

			var n = Math.Min(source.Length, BlockSize4);

			fixed (byte* pOut = destination)
			fixed (byte* pSource = source)
			fixed (byte* pBuffer = _buffer)
			{
				IntrinsicsUtils.Xor(pSource, pBuffer, pOut, n);
			}

			_gHash.Update(destination[..n]);

			source = source[n..];
			destination = destination[n..];
		}

		BinaryPrimitives.WriteUInt64BigEndian(_buffer, (ulong)associatedData.Length << 3);
		BinaryPrimitives.WriteUInt64BigEndian(_buffer.AsSpan(8), length);

		_gHash.Update(_buffer.AsSpan(0, TagSize));
		_gHash.GetMac(_buffer);

		fixed (byte* pTag = tag)
		fixed (byte* pBuffer = _buffer)
		{
			IntrinsicsUtils.Xor16(pTag, pBuffer, pTag);
		}
	}

	public unsafe void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag,
		Span<byte> destination, ReadOnlySpan<byte> associatedData = default)
	{
		if (nonce.Length != NonceSize)
		{
			throw new ArgumentException(@"Nonce size must be 12 bytes", nameof(nonce));
		}

		if (destination.Length != source.Length)
		{
			throw new ArgumentException(@"Plaintext and ciphertext must have the same length.", nameof(destination));
		}

		var length = (ulong)source.Length << 3;

		var counterBlock = _counterBlock.AsSpan(0, BlockSize4);
		var counter0 = counterBlock.Slice(12, 4);
		var counter1 = counterBlock.Slice(28, 4);
		var counter2 = counterBlock.Slice(44, 4);
		var counter3 = counterBlock.Slice(60, 4);

		nonce.CopyTo(counterBlock);
		nonce.CopyTo(counterBlock[16..]);
		nonce.CopyTo(counterBlock[32..]);
		nonce.CopyTo(counterBlock[48..]);

		counter0[0] = 0;
		counter0[1] = 0;
		counter0[2] = 0;
		counter0[3] = 1;

		counter1[0] = 0;
		counter1[1] = 0;
		counter1[2] = 0;
		counter1[3] = 3;

		counter2[0] = 0;
		counter2[1] = 0;
		counter2[2] = 0;
		counter2[3] = 4;

		counter3[0] = 0;
		counter3[1] = 0;
		counter3[2] = 0;
		counter3[3] = 5;

		_crypto.Encrypt(counterBlock, _tagBuffer);
		counter0[3] = 2;

		uint c3 = 5;

		_gHash.Update(associatedData);

		while (!source.IsEmpty)
		{
			_crypto.Encrypt4(counterBlock, _buffer);
			var c0 = c3 + 1;
			var c1 = c0 + 1;
			var c2 = c1 + 1;
			c3 = c2 + 1;
			BinaryPrimitives.WriteUInt32BigEndian(counter0, c0);
			BinaryPrimitives.WriteUInt32BigEndian(counter1, c1);
			BinaryPrimitives.WriteUInt32BigEndian(counter2, c2);
			BinaryPrimitives.WriteUInt32BigEndian(counter3, c3);

			var n = Math.Min(source.Length, BlockSize4);

			_gHash.Update(source[..n]);

			fixed (byte* pOut = destination)
			fixed (byte* pSource = source)
			fixed (byte* pBuffer = _buffer)
			{
				IntrinsicsUtils.Xor(pSource, pBuffer, pOut, n);
			}

			source = source[n..];
			destination = destination[n..];
		}

		BinaryPrimitives.WriteUInt64BigEndian(_buffer, (ulong)associatedData.Length << 3);
		BinaryPrimitives.WriteUInt64BigEndian(_buffer.AsSpan(8), length);

		_gHash.Update(_buffer.AsSpan(0, TagSize));
		_gHash.GetMac(_buffer);

		fixed (byte* pTag = _tagBuffer)
		fixed (byte* pBuffer = _buffer)
		{
			IntrinsicsUtils.Xor16(pTag, pBuffer, pTag);
		}

		if (!CryptographicOperations.FixedTimeEquals(_tagBuffer.AsSpan(0, TagSize), tag))
		{
			throw new ArgumentException(@"Unable to decrypt input with these parameters.");
		}
	}

	public void Dispose()
	{
		_crypto.Dispose();
		_gHash.Dispose();

		ArrayPool<byte>.Shared.Return(_buffer);
		ArrayPool<byte>.Shared.Return(_tagBuffer);
		ArrayPool<byte>.Shared.Return(_counterBlock);
	}
}
