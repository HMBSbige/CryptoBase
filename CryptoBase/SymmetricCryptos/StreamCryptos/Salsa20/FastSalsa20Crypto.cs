using System;
using System.Buffers.Binary;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20
{
	public class FastSalsa20Crypto : Salsa20Crypto
	{
		public bool IsSupport => Sse2.IsSupported;

		public FastSalsa20Crypto(byte[] key, byte[] iv) : base(key, iv)
		{
			Reset();
		}

		protected override unsafe void UpdateKeyStream(uint[] state, byte[] keyStream)
		{
			fixed (uint* x = state)
			fixed (byte* s = keyStream)
			{
				IntrinsicsUtils.SalsaCore(x, s, Rounds);
			}
		}

		public sealed override void Reset()
		{
			Index = 0;
			State[8] = State[9] = 0;

			var keyLength = Key.Length;

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

			var key = Key.Span;
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

			var iv = Iv.Span;
			State[6] = BinaryPrimitives.ReadUInt32LittleEndian(iv);
			State[7] = BinaryPrimitives.ReadUInt32LittleEndian(iv.Slice(4));
		}
	}
}
