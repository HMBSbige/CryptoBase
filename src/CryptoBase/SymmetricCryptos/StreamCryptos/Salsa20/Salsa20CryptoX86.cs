namespace CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20;

public class Salsa20CryptoX86 : Salsa20Crypto
{
	public Salsa20CryptoX86(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		Init(key, iv);
		Reset();
	}

	private void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		ReadOnlySpan<uint> keySpan = MemoryMarshal.Cast<byte, uint>(key);
		int keyLength = key.Length;

		switch (keyLength)
		{
			case 16:
			{
				State[0] = Sigma16[0];
				State[5] = Sigma16[1];
				State[10] = Sigma16[2];
				State[15] = Sigma16[3];
				State[11] = keySpan[0];
				State[12] = keySpan[1];
				State[13] = keySpan[2];
				State[14] = keySpan[3];
				break;
			}
			case 32:
			{
				State[0] = Sigma32[0];
				State[5] = Sigma32[1];
				State[10] = Sigma32[2];
				State[15] = Sigma32[3];
				State[11] = keySpan[4];
				State[12] = keySpan[5];
				State[13] = keySpan[6];
				State[14] = keySpan[7];
				break;
			}
			default:
			{
				ThrowHelper.ThrowArgumentOutOfRangeException<int>(nameof(key));
				return;
			}
		}

		State[1] = keySpan[0];
		State[2] = keySpan[1];
		State[3] = keySpan[2];
		State[4] = keySpan[3];

		ReadOnlySpan<uint> ivSpan = MemoryMarshal.Cast<byte, uint>(iv);
		State[6] = ivSpan[0];
		State[7] = ivSpan[1];
	}

	public sealed override void Reset()
	{
		Index = 0;
		Unsafe.As<uint, ulong>(ref Unsafe.Add(ref MemoryMarshal.GetArrayDataReference(State), 8)) = 0;
	}

	protected override int UpdateBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int processed = 0;
		int length = source.Length;
		Span<uint> stateSpan = State.AsSpan(0, StateSize);

		if (Avx2.IsSupported)
		{
			if (length >= 512)
			{
				int offset = Salsa20Utils.SalsaCore512(Rounds, stateSpan, source, destination);
				processed += offset;
				length -= offset;
			}

			while (length >= 128)
			{
				Salsa20Utils.SalsaCore128(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed));

				processed += 128;
				length -= 128;
			}
		}

		if (Sse2.IsSupported)
		{
			if (length >= 256)
			{
				int offset = Salsa20Utils.SalsaCore256(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed));
				processed += offset;
				length -= offset;
			}

			while (length >= 64)
			{
				Salsa20Utils.SalsaCore64(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed));

				processed += 64;
				length -= 64;
			}
		}

		return processed;
	}

	protected override void UpdateKeyStream()
	{
		Salsa20Utils.UpdateKeyStream(State, KeyStream, Rounds);
	}
}
