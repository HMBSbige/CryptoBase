using System.Runtime.InteropServices;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20Original;

public abstract class ChaCha20OriginalCrypto : ChaCha20CryptoBase
{
	public override string Name => @"ChaCha20Original";

	protected ChaCha20OriginalCrypto(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		Init(key, iv);
		Reset();
	}

	private void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		var keySpan = MemoryMarshal.Cast<byte, uint>(key);
		var keyLength = key.Length;
		switch (keyLength)
		{
			case 16:
			{
				State[0] = Sigma16[0];
				State[1] = Sigma16[1];
				State[2] = Sigma16[2];
				State[3] = Sigma16[3];
				State[8] = keySpan[0];
				State[9] = keySpan[1];
				State[10] = keySpan[2];
				State[11] = keySpan[3];
				break;
			}
			case 32:
			{
				State[0] = Sigma32[0];
				State[1] = Sigma32[1];
				State[2] = Sigma32[2];
				State[3] = Sigma32[3];
				State[8] = keySpan[4];
				State[9] = keySpan[5];
				State[10] = keySpan[6];
				State[11] = keySpan[7];
				break;
			}
			default:
			{
				throw new ArgumentException(@"Key length requires 16 or 32 bytes");
			}
		}

		State[4] = keySpan[0];
		State[5] = keySpan[1];
		State[6] = keySpan[2];
		State[7] = keySpan[3];

		var ivSpan = MemoryMarshal.Cast<byte, uint>(iv);
		State[14] = ivSpan[0];
		State[15] = ivSpan[1];
	}

	public sealed override void Reset()
	{
		Index = 0;
		State[12] = State[13] = 0;
	}

	protected override unsafe void IncrementCounter(uint* state)
	{
		ChaCha20Utils.IncrementCounterOriginal(state);
	}
}
