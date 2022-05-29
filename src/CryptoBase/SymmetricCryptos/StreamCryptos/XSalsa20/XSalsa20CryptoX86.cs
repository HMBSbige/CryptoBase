namespace CryptoBase.SymmetricCryptos.StreamCryptos.XSalsa20;

public class XSalsa20CryptoX86 : Salsa20Crypto
{
	public override string Name => @"XSalsa20";

	public override int IvSize => 24;

	public XSalsa20CryptoX86(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		Init(key, iv);
		Reset();
	}

	private void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		if (key.Length != 32)
		{
			throw new ArgumentException(@"Key length requires 32 bytes");
		}

		var span = State.AsSpan();

		State[0] = Sigma32[0];
		State[5] = Sigma32[1];
		State[10] = Sigma32[2];
		State[15] = Sigma32[3];

		var keySpan = MemoryMarshal.Cast<byte, uint>(key);
		keySpan[..4].CopyTo(span[1..]);
		keySpan[4..].CopyTo(span[11..]);

		var ivSpan = MemoryMarshal.Cast<byte, uint>(iv);
		ivSpan[..4].CopyTo(span[6..]);

		SalsaRound(State);

		State[1] = State[0];
		State[2] = State[5];
		State[3] = State[10];
		State[4] = State[15];

		span.Slice(6, 4).CopyTo(span[11..]);

		State[6] = ivSpan[4];
		State[7] = ivSpan[5];

		State[8] = ivSpan[2];
		State[9] = ivSpan[3];

		State[0] = Sigma32[0];
		State[5] = Sigma32[1];
		State[10] = Sigma32[2];
		State[15] = Sigma32[3];
	}

	public sealed override void Reset()
	{
		Index = 0;
		State[8] = State[9] = 0;
	}

	protected virtual unsafe void SalsaRound(uint[] x)
	{
		fixed (uint* p = x)
		{
			Salsa20Utils.SalsaRound(p, Rounds);
		}
	}

	protected override unsafe void UpdateBlocks(ref uint* state, ref byte* source, ref byte* destination, ref int length)
	{
		if (Avx.IsSupported && Avx2.IsSupported)
		{
			if (length >= 512)
			{
				Salsa20Utils.SalsaCore512(Rounds, state, ref source, ref destination, ref length);
			}

			while (length >= 128)
			{
				Salsa20Utils.SalsaCore128(Rounds, state, source, destination);

				source += 128;
				destination += 128;
				length -= 128;
			}
		}

		if (Sse2.IsSupported)
		{
			if (length >= 256)
			{
				Salsa20Utils.SalsaCore256(Rounds, state, ref source, ref destination, ref length);
			}

			while (length >= 64)
			{
				Salsa20Utils.SalsaCore64(Rounds, state, source, destination);

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
			Salsa20Utils.UpdateKeyStream(x, s, Rounds);
		}
	}

	protected override unsafe void Xor(byte* stream, byte* source, byte* destination, int length)
	{
		IntrinsicsUtils.Xor(stream, source, destination, length);
	}
}
