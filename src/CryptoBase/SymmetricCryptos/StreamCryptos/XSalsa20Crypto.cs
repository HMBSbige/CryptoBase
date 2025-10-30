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

		Span<uint> state = State.Span;

		state[0] = Sigma32[0];
		state[5] = Sigma32[1];
		state[10] = Sigma32[2];
		state[15] = Sigma32[3];

		ReadOnlySpan<uint> keySpan = MemoryMarshal.Cast<byte, uint>(key);
		keySpan.Slice(0, 4).CopyTo(state.Slice(1));
		keySpan.Slice(4).CopyTo(state.Slice(11));

		ReadOnlySpan<uint> ivSpan = MemoryMarshal.Cast<byte, uint>(iv);
		ivSpan.Slice(0, 4).CopyTo(state.Slice(6));

		if (Sse2.IsSupported)
		{
			Salsa20Utils.SalsaRound(State.Span, Rounds);
		}
		else
		{
			Salsa20Utils.SalsaRound(Rounds, State.Span);
		}

		state[1] = state[0];
		state[2] = state[5];
		state[3] = state[10];
		state[4] = state[15];

		state.Slice(6, 4).CopyTo(state.Slice(11));

		state[6] = ivSpan[4];
		state[7] = ivSpan[5];

		state[8] = ivSpan[2];
		state[9] = ivSpan[3];

		state[0] = Sigma32[0];
		state[5] = Sigma32[1];
		state[10] = Sigma32[2];
		state[15] = Sigma32[3];
	}
}
