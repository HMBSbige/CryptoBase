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

		Span<uint> span = State.AsSpan(0, StateSize);

		State[0] = Sigma32[0];
		State[5] = Sigma32[1];
		State[10] = Sigma32[2];
		State[15] = Sigma32[3];

		ReadOnlySpan<uint> keySpan = MemoryMarshal.Cast<byte, uint>(key);
		keySpan.Slice(0, 4).CopyTo(span.Slice(1));
		keySpan.Slice(4).CopyTo(span.Slice(11));

		ReadOnlySpan<uint> ivSpan = MemoryMarshal.Cast<byte, uint>(iv);
		ivSpan.Slice(0, 4).CopyTo(span.Slice(6));

		SalsaRound(State);

		State[1] = State[0];
		State[2] = State[5];
		State[3] = State[10];
		State[4] = State[15];

		span.Slice(6, 4).CopyTo(span.Slice(11));

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
		Unsafe.As<uint, ulong>(ref Unsafe.Add(ref MemoryMarshal.GetArrayDataReference(State), 8)) = 0;
	}

	protected virtual void SalsaRound(uint[] x)
	{
		Salsa20Utils.SalsaRound(x, Rounds);
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
