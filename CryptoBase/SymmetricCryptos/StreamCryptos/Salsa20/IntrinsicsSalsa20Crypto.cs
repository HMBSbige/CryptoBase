using CryptoBase.Abstractions.SymmetricCryptos;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20
{
	public class IntrinsicsSalsa20Crypto : Salsa20CryptoBase
	{
		private readonly ReadOnlyMemory<byte> _key;
		private readonly ReadOnlyMemory<byte> _iv;

		protected byte Rounds { get; init; } = 20;

		public bool IsSupport => Sse2.IsSupported;

		private readonly uint[] _state;
		private readonly byte[] _keyStream;

		private int _index;

		public IntrinsicsSalsa20Crypto(byte[] key, byte[] iv) : base(key, iv)
		{
			_key = key;
			_iv = iv;

			_state = ArrayPool<uint>.Shared.Rent(StateSize);
			_keyStream = ArrayPool<byte>.Shared.Rent(StateSize * sizeof(uint));

			Reset();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		protected override unsafe void Update(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			if (destination.Length < source.Length)
			{
				throw new ArgumentException(string.Empty, nameof(destination));
			}

			while (source.Length > 0)
			{
				if (_index == 0)
				{
					UpdateKeyStream(_state, _keyStream);
				}
				var r = _keyStream.AsSpan(_index);

				fixed (byte* pStream = r)
				fixed (byte* pSource = source)
				fixed (byte* pDestination = destination)
				{
					IntrinsicsUtils.Xor(pStream, pSource, pDestination, Math.Min(r.Length, source.Length));
				}

				if (source.Length < r.Length)
				{
					_index += source.Length;
					return;
				}

				_index = 0;
				source = source.Slice(r.Length);
			}
		}

		protected virtual unsafe void UpdateKeyStream(uint[] state, byte[] keyStream)
		{
			fixed (uint* x = state)
			fixed (byte* s = keyStream)
			{
				IntrinsicsUtils.SalsaCore(x, s, Rounds);
			}
		}

		public sealed override void Reset()
		{
			_index = 0;
			_state[8] = _state[9] = 0;

			var keyLength = _key.Length;

			switch (keyLength)
			{
				case 16:
				{
					_state[0] = Sigma16[0];
					_state[5] = Sigma16[1];
					_state[10] = Sigma16[2];
					_state[15] = Sigma16[3];
					break;
				}
				case 32:
				{
					_state[0] = Sigma32[0];
					_state[5] = Sigma32[1];
					_state[10] = Sigma32[2];
					_state[15] = Sigma32[3];
					break;
				}
				default:
				{
					throw new ArgumentException(@"Key length requires 16 or 32 bytes");
				}
			}

			var key = _key.Span;
			_state[1] = BinaryPrimitives.ReadUInt32LittleEndian(key);
			_state[2] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(4));
			_state[3] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(8));
			_state[4] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(12));

			if (keyLength == 32)
			{
				key = key.Slice(16);
			}

			_state[11] = BinaryPrimitives.ReadUInt32LittleEndian(key);
			_state[12] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(4));
			_state[13] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(8));
			_state[14] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(12));

			var iv = _iv.Span;
			_state[6] = BinaryPrimitives.ReadUInt32LittleEndian(iv);
			_state[7] = BinaryPrimitives.ReadUInt32LittleEndian(iv.Slice(4));
		}

		public override void Dispose()
		{
			base.Dispose();

			ArrayPool<uint>.Shared.Return(_state);
			ArrayPool<byte>.Shared.Return(_keyStream);
		}
	}
}
