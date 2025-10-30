namespace CryptoBase.SymmetricCryptos.StreamCryptos;

public class XSalsa20Crypto : Salsa20Crypto
{
	public override string Name => @"XSalsa20";

	public override int IvSize => 24;

	public XSalsa20Crypto(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : base(key, iv)
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

		if (Sse2.IsSupported)
		{
			Salsa20Utils.SalsaRound(State, Rounds);
		}
		else
		{
			Salsa20Utils.SalsaRound(Rounds, State);
		}

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
}
