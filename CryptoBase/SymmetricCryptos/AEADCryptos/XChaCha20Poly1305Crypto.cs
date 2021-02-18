using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.Macs.Poly1305;
using CryptoBase.SymmetricCryptos.StreamCryptos.XChaCha20;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace CryptoBase.SymmetricCryptos.AEADCryptos
{
	public class XChaCha20Poly1305Crypto : IAEADCrypto
	{
		public string Name => @"XChaCha20-Poly1305";

		private readonly XChaCha20Crypto _chacha20;

		public const int KeySize = 32;
		public const int NonceSize = 24;
		public const int TagSize = 16;

		private static ReadOnlySpan<byte> Init => new byte[Poly1305.KeySize];

		private readonly byte[] _buffer;

		public XChaCha20Poly1305Crypto(byte[] key)
		{
			if (key.Length < KeySize)
			{
				throw new ArgumentException(@"Key length must be 32 bytes.", nameof(key));
			}

			_chacha20 = StreamCryptoCreate.XChaCha20(key);

			_buffer = ArrayPool<byte>.Shared.Rent(32);
		}

		[MethodImpl(MethodImplOptions.AggressiveOptimization)]
		public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source,
			Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
		{
			if (nonce.Length != NonceSize)
			{
				throw new ArgumentException(@"Nonce size must be 24 bytes", nameof(nonce));
			}

			if (destination.Length != source.Length)
			{
				throw new ArgumentException(string.Empty, nameof(destination));
			}

			_chacha20.SetIV(nonce);

			_chacha20.SetCounter(1);
			_chacha20.Update(source, destination);

			var buffer = _buffer.AsSpan(0, Poly1305.KeySize);
			_chacha20.SetCounter(0);
			_chacha20.Update(Init, buffer);
			using var poly1305 = new Poly1305(buffer);

			poly1305.Update(associatedData);
			poly1305.Update(destination);

			Span<byte> block = _buffer.AsSpan(Poly1305.BlockSize);
			BinaryPrimitives.WriteUInt64LittleEndian(block, (ulong)associatedData.Length);
			BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(8), (ulong)source.Length);
			poly1305.Update(block);

			poly1305.GetMac(tag);
		}

		[MethodImpl(MethodImplOptions.AggressiveOptimization)]
		public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag,
			Span<byte> destination, ReadOnlySpan<byte> associatedData = default)
		{
			if (nonce.Length != NonceSize)
			{
				throw new ArgumentException(@"Nonce size must be 24 bytes", nameof(nonce));
			}

			if (destination.Length != source.Length)
			{
				throw new ArgumentException(string.Empty, nameof(destination));
			}

			_chacha20.SetIV(nonce);

			var buffer = _buffer.AsSpan(0, Poly1305.KeySize);
			_chacha20.SetCounter(0);
			_chacha20.Update(Init, buffer);
			using var poly1305 = new Poly1305(buffer);

			poly1305.Update(associatedData);
			poly1305.Update(source);

			Span<byte> block = _buffer.AsSpan(TagSize);
			BinaryPrimitives.WriteUInt64LittleEndian(block, (ulong)associatedData.Length);
			BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(8), (ulong)source.Length);
			poly1305.Update(block);

			poly1305.GetMac(block);

			if (!block.SequenceEqual(tag))
			{
				throw new ArgumentException(@"Unable to decrypt input with these parameters.");
			}

			_chacha20.SetCounter(1);
			_chacha20.Update(source, destination);
		}

		public void Dispose()
		{
			_chacha20.Dispose();

			ArrayPool<byte>.Shared.Return(_buffer);
		}
	}
}
