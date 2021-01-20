using CryptoBase.Abstractions.SymmetricCryptos;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20
{
	public class SlowSalsa20Crypto : Salsa20CryptoBase
	{
		/// <summary>
		/// expand 16-byte k
		/// </summary>
		protected readonly static uint[] Sigma16 = { 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 };

		/// <summary>
		/// expand 32-byte k
		/// </summary>
		protected readonly static uint[] Sigma32 = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

		private readonly ReadOnlyMemory<byte> _key;
		private readonly ReadOnlyMemory<byte> _iv;

		private const int Rounds = 20;
		private const int StateSize = 16; // 64 bytes
		protected uint[] State; // state
		protected uint[] WorkState; // working state
		private byte[] keyStream; // state

		private int _index;

		public SlowSalsa20Crypto(byte[] key, byte[] iv) : base(key, iv)
		{
			_key = key;
			_iv = iv;

			State = ArrayPool<uint>.Shared.Rent(StateSize);
			WorkState = ArrayPool<uint>.Shared.Rent(StateSize);
			keyStream = ArrayPool<byte>.Shared.Rent(StateSize * sizeof(uint));

			Init();
		}

		protected override void Update(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			for (var i = 0; i < source.Length; ++i)
			{
				if (_index == 0)
				{
					SalsaCore(Rounds, State, WorkState);
					var span = keyStream.AsSpan();
					for (var j = 0; j < StateSize; j++)
					{
						BinaryPrimitives.WriteUInt32LittleEndian(span, WorkState[j]);
						span = span.Slice(4);
					}

					if (++State[8] == 0)
					{
						++State[9];
					}
				}

				destination[i] = (byte)(keyStream[_index] ^ source[i]);
				_index = (_index + 1) & 0b111111;
			}
		}

		private void Init()
		{
			_index = 0;
			State[8] = State[9] = 0;

			var keyLength = _key.Length;

			switch (keyLength)
			{
				case 16:
				{
					State[0] = Sigma16[0];
					State[5] = Sigma16[1];
					State[10] = Sigma16[2];
					State[15] = Sigma16[3];
					break;
				}
				case 32:
				{
					State[0] = Sigma32[0];
					State[5] = Sigma32[1];
					State[10] = Sigma32[2];
					State[15] = Sigma32[3];
					break;
				}
				default:
				{
					throw new ArgumentException(@"Key length requires 16 or 32 bytes");
				}
			}

			var key = _key.Span;
			State[1] = BinaryPrimitives.ReadUInt32LittleEndian(key);
			State[2] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(4));
			State[3] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(8));
			State[4] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(12));

			if (keyLength == 32)
			{
				key = key.Slice(16);
			}

			State[11] = BinaryPrimitives.ReadUInt32LittleEndian(key);
			State[12] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(4));
			State[13] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(8));
			State[14] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(12));

			var iv = _iv.Span;
			State[6] = BinaryPrimitives.ReadUInt32LittleEndian(iv);
			State[7] = BinaryPrimitives.ReadUInt32LittleEndian(iv.Slice(4));
		}

		public override void Reset()
		{
			Init();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private static void SalsaCore(int rounds, uint[] state, uint[] x)
		{
			state.AsSpan().CopyTo(x);
			for (var i = 0; i < rounds; i += 2)
			{
				QuarterRound(x, 4, 0, 12, 8);
				QuarterRound(x, 9, 5, 1, 13);
				QuarterRound(x, 14, 10, 6, 2);
				QuarterRound(x, 3, 15, 11, 7);

				QuarterRound(x, 1, 0, 3, 2);
				QuarterRound(x, 6, 5, 4, 7);
				QuarterRound(x, 11, 10, 9, 8);
				QuarterRound(x, 12, 15, 14, 13);
			}

			for (var i = 0; i < StateSize; ++i)
			{
				x[i] += state[i];
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static void QuarterRound(uint[] x, int a, int b, int c, int d)
		{
			Step(ref x[a], x[b], x[c], 7);
			Step(ref x[d], x[a], x[b], 9);
			Step(ref x[c], x[d], x[a], 13);
			Step(ref x[b], x[c], x[d], 18);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static void Step(ref uint a, uint b, uint c, byte i)
		{
			a ^= (b + c).RotateLeft(i);
		}

		public override void Dispose()
		{
			base.Dispose();

			ArrayPool<uint>.Shared.Return(State);
			ArrayPool<uint>.Shared.Return(WorkState);
			ArrayPool<byte>.Shared.Return(keyStream);
		}
	}
}
