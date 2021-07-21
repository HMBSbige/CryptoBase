using CryptoBase.Abstractions.SymmetricCryptos;
using System;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes
{
	public class CTRStreamMode : IStreamBlockCryptoMode
	{
		public string Name => InternalBlockCrypto.Name + @"-CTR";

		public IBlockCrypto InternalBlockCrypto { get; init; }

		public ReadOnlyMemory<byte> Iv { get; init; }

		private readonly byte[] _counter;
		private readonly byte[] _keyStream;

		private int _index;

		private readonly int _blockSize;
		private readonly int _blockSize2;
		private readonly int _blockSize3;
		private readonly int _blockSize4;

		public CTRStreamMode(IBlockCrypto crypto, ReadOnlySpan<byte> iv)
		{
			InternalBlockCrypto = crypto;
			Iv = iv.ToArray();

			_blockSize = InternalBlockCrypto.BlockSize;
			_blockSize2 = _blockSize << 1;
			_blockSize3 = _blockSize2 + _blockSize;
			_blockSize4 = _blockSize2 << 1;

			if (Iv.Length > _blockSize)
			{
				throw new ArgumentException($@"IV length > {_blockSize} bytes", nameof(iv));
			}

			_counter = ArrayPool<byte>.Shared.Rent(_blockSize4);
			_keyStream = ArrayPool<byte>.Shared.Rent(_blockSize4);

			Reset();
		}

		public unsafe void Update(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			if (destination.Length < source.Length)
			{
				throw new ArgumentException(string.Empty, nameof(destination));
			}

			var length = source.Length;
			fixed (byte* pStream = _keyStream)
			fixed (byte* pSource = source)
			fixed (byte* pDestination = destination)
			{
				Update(length, pStream, pSource, pDestination);
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private unsafe void Update(int length, byte* stream, byte* source, byte* destination)
		{
			while (length > 0)
			{
				if (_index == 0)
				{
					UpdateKeyStream();
				}

				var r = _blockSize4 - _index;
				IntrinsicsUtils.Xor(stream + _index, source, destination, Math.Min(r, length));

				if (length < r)
				{
					_index += length;
					return;
				}

				_index = 0;
				length -= r;
				source += r;
				destination += r;
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private void UpdateKeyStream()
		{
			InternalBlockCrypto.Encrypt4(_counter, _keyStream);

			UpdateCounter();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private void UpdateCounter()
		{
			_counter.IncrementBe4(0, _blockSize);
			_counter.IncrementBe4(_blockSize, _blockSize2);
			_counter.IncrementBe4(_blockSize2, _blockSize3);
			_counter.IncrementBe4(_blockSize3, _blockSize4);
		}

		public void Reset()
		{
			InternalBlockCrypto.Reset();
			_index = 0;

			for (var i = Iv.Length; i < _blockSize; ++i)
			{
				_counter[i] = 0;
			}

			var c = _counter.AsSpan();
			Iv.Span.CopyTo(c);

			var c0 = c[.._blockSize];

			var c1 = c.Slice(_blockSize, _blockSize);
			c0.CopyTo(c1);
			c1.IncrementBe();

			var c2 = c.Slice(_blockSize2, _blockSize);
			c1.CopyTo(c2);
			c2.IncrementBe();

			var c3 = c.Slice(_blockSize3, _blockSize);
			c2.CopyTo(c3);
			c3.IncrementBe();
		}

		public void Dispose()
		{
			InternalBlockCrypto.Dispose();

			ArrayPool<byte>.Shared.Return(_counter);
			ArrayPool<byte>.Shared.Return(_keyStream);
		}
	}
}
