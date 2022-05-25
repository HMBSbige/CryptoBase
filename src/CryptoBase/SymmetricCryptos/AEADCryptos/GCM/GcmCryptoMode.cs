using CryptoBase.Abstractions;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.Macs.GHash;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CryptoBase.SymmetricCryptos.AEADCryptos.GCM;

public class GcmCryptoMode : IAEADCrypto
{
	public string Name => _crypto.Name + @"-GCM";

	public const int BlockSize = 16;
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
		if (crypto.BlockSize is not BlockSize)
		{
			throw new ArgumentException($@"Crypto block size must be {BlockSize} bytes.", nameof(crypto));
		}
		_crypto = crypto;

		_buffer = ArrayPool<byte>.Shared.Rent(BlockSize);
		_tagBuffer = ArrayPool<byte>.Shared.Rent(TagSize);
		_counterBlock = ArrayPool<byte>.Shared.Rent(BlockSize);

		_crypto.Encrypt(Init, _buffer);
		_gHash = GHashUtils.Create(_buffer);
	}

	public unsafe void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source,
		Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
	{
		CheckInput(nonce, source, destination);

		ulong length = (ulong)source.Length << 3;

		Span<byte> counterBlock = _counterBlock.AsSpan(0, BlockSize);
		Span<byte> counter = counterBlock.Slice(12, 4);

		nonce.CopyTo(counterBlock);

		counter[0] = 0;
		counter[1] = 0;
		counter[2] = 0;
		counter[3] = 1;

		_crypto.Encrypt(counterBlock, tag);
		counter[3] = 2;
		uint c = 2;
		_gHash.Update(associatedData);

		while (!source.IsEmpty)
		{
			_crypto.Encrypt(counterBlock, _buffer);
			++c;
			BinaryPrimitives.WriteUInt32BigEndian(counter, c);

			int n = Math.Min(source.Length, BlockSize);

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
		CheckInput(nonce, source, destination);

		ulong length = (ulong)source.Length << 3;

		Span<byte> counterBlock = _counterBlock.AsSpan(0, BlockSize);
		Span<byte> counter0 = counterBlock.Slice(12, 4);

		nonce.CopyTo(counterBlock);

		counter0[0] = 0;
		counter0[1] = 0;
		counter0[2] = 0;
		counter0[3] = 1;

		_crypto.Encrypt(counterBlock, _tagBuffer);
		counter0[3] = 2;
		uint c = 2;
		_gHash.Update(associatedData);

		while (!source.IsEmpty)
		{
			_crypto.Encrypt(counterBlock, _buffer);
			++c;
			BinaryPrimitives.WriteUInt32BigEndian(counter0, c);

			int n = Math.Min(source.Length, BlockSize);

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
		_gHash.Dispose();

		ArrayPool<byte>.Shared.Return(_buffer);
		ArrayPool<byte>.Shared.Return(_tagBuffer);
		ArrayPool<byte>.Shared.Return(_counterBlock);

		GC.SuppressFinalize(this);
	}
}
