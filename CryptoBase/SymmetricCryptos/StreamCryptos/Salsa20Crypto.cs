using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.StreamCryptos
{
	public abstract class Salsa20Crypto : SnuffleCrypto
	{
		public override string Name => @"Salsa20";

		protected Salsa20Crypto(byte[] key, byte[] iv) : base(key, iv) { }

		protected override unsafe void SnuffleCore64(uint* state, byte* source, byte* destination)
		{
			Salsa20Utils.SalsaCore64(Rounds, state, source, destination);
		}

		protected override unsafe void SnuffleCore128(uint* state, byte* source, byte* destination)
		{
			Salsa20Utils.SalsaCore128(Rounds, state, source, destination);
		}

		protected override unsafe void SnuffleCore256(uint* state, ref byte* source, ref byte* destination, ref int length)
		{
			Salsa20Utils.SalsaCore256(Rounds, state, ref source, ref destination, ref length);
		}

		protected override unsafe void SnuffleCore512(uint* state, ref byte* source, ref byte* destination, ref int length)
		{
			Salsa20Utils.SalsaCore512(Rounds, state, ref source, ref destination, ref length);
		}

		protected override unsafe void UpdateKeyStream()
		{
			if (IsSupport)
			{
				if (Sse2.IsSupported)
				{
					fixed (uint* x = State)
					fixed (byte* s = KeyStream)
					{
						Salsa20Utils.UpdateKeyStream(x, s, Rounds);
					}
					return;
				}
			}

			Salsa20Utils.UpdateKeyStream(Rounds, State, KeyStream);
		}

		protected override unsafe void IncrementCounter(uint* state)
		{
			if (++*(state + 8) == 0)
			{
				++*(state + 9);
			}
		}
	}
}
