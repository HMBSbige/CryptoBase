using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.StreamCryptos
{
	public abstract class ChaCha20CryptoBase : SnuffleCrypto
	{
		protected ChaCha20CryptoBase(byte[] key, byte[] iv) : base(key, iv) { }

		protected override unsafe void UpdateKeyStream()
		{
			if (IsSupport)
			{
				if (Sse2.IsSupported)
				{
					fixed (uint* x = State)
					fixed (byte* s = KeyStream)
					{
						ChaCha20Utils.UpdateKeyStream(x, s, Rounds);
					}
					return;
				}
			}

			ChaCha20Utils.UpdateKeyStream(Rounds, State, KeyStream);
		}
	}
}
