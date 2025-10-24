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
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, 32, nameof(key));

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

	protected virtual void SalsaRound(uint[] x)
	{
		Salsa20Utils.SalsaRound(x.AsSpan(), Rounds);
	}

	protected override int UpdateBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int processed = 0;
		int length = source.Length;
		Span<uint> stateSpan = State.AsSpan(0, 16);

		if (Avx.IsSupported && Avx2.IsSupported)
		{
			if (length >= 512)
			{
				int tempLength = length;
				int tempSourceOffset = 0;
				int tempDestOffset = 0;
				Salsa20Utils.SalsaCore512(Rounds, stateSpan, source, destination, ref tempLength, ref tempSourceOffset, ref tempDestOffset);
				processed += tempSourceOffset;
				length = tempLength;
			}

			while (length >= 128)
			{
				Salsa20Utils.SalsaCore128(Rounds, stateSpan, source.Slice(processed, 128), destination.Slice(processed, 128));

				processed += 128;
				length -= 128;
			}
		}

		if (Sse2.IsSupported)
		{
			if (length >= 256)
			{
				int tempLength = length;
				int tempSourceOffset = 0;
				int tempDestOffset = 0;
				Salsa20Utils.SalsaCore256(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed), ref tempLength, ref tempSourceOffset, ref tempDestOffset);
				processed += tempSourceOffset;
				length = tempLength;
			}

			while (length >= 64)
			{
				Salsa20Utils.SalsaCore64(Rounds, stateSpan, source.Slice(processed, 64), destination.Slice(processed, 64));

				processed += 64;
				length -= 64;
			}
		}

		return processed;
	}

	protected override void UpdateKeyStream()
	{
		Salsa20Utils.UpdateKeyStream(State.AsSpan(0, 16), KeyStream.AsSpan(0, 64), Rounds);
	}
}
