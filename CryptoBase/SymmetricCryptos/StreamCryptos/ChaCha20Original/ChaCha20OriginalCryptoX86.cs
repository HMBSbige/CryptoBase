using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20Original
{
	public class ChaCha20OriginalCryptoX86 : ChaCha20OriginalCryptoSF
	{
		public ChaCha20OriginalCryptoX86(byte[] key, byte[] iv) : base(key, iv) { }

		protected override unsafe void UpdateBlocks(ref uint* state, ref byte* source, ref byte* destination, ref int length)
		{
			if (Avx.IsSupported && Avx2.IsSupported)
			{
				if (length >= 512)
				{
					ChaCha20Utils.ChaChaCoreOriginal512(Rounds, state, ref source, ref destination, ref length);
				}

				while (length >= 128)
				{
					ChaCha20Utils.ChaChaCoreOriginal128(Rounds, state, source, destination);

					source += 128;
					destination += 128;
					length -= 128;
				}
			}

			if (Sse2.IsSupported)
			{
				if (length >= 256)
				{
					ChaCha20Utils.ChaChaCoreOriginal256(Rounds, state, ref source, ref destination, ref length);
				}

				while (length >= 64)
				{
					ChaCha20Utils.ChaChaCoreOriginal64(Rounds, state, source, destination);

					source += 64;
					destination += 64;
					length -= 64;
				}
			}
		}

		protected override unsafe void UpdateKeyStream()
		{
			fixed (uint* x = State)
			fixed (byte* s = KeyStream)
			{
				ChaCha20Utils.UpdateKeyStream(x, s, Rounds);
			}
		}

		protected override unsafe void Xor(byte* stream, byte* source, byte* destination, int length)
		{
			IntrinsicsUtils.Xor(stream, source, destination, length);
		}
	}
}
