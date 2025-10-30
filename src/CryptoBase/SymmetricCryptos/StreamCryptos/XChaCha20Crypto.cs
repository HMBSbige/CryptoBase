namespace CryptoBase.SymmetricCryptos.StreamCryptos;

public class XChaCha20Crypto : ChaCha20OriginalCrypto
{
	public override string Name => @"XChaCha20";

	public override int IvSize => 24;

	private readonly ReadOnlyMemory<byte> _key;

	public XChaCha20Crypto(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : base(key, iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, 32, nameof(key));

		_key = key.ToArray();

		SetIV(iv);
		Reset();
	}

	private void ChaChaRound(in Span<uint> x)
	{
		if (Sse2.IsSupported)
		{
			ChaCha20Utils.ChaChaRound(x, Rounds);
		}
		else
		{
			ChaCha20Utils.ChaChaRound(Rounds, x);
		}
	}

	public void SetIV(ReadOnlySpan<byte> iv)
	{
		Span<uint> state = State.Span;
		Span<uint> sigma = Sigma32.AsSpan();

		sigma.CopyTo(state);

		ReadOnlySpan<uint> keySpan = MemoryMarshal.Cast<byte, uint>(_key.Span);
		keySpan.CopyTo(state.Slice(4));

		ReadOnlySpan<uint> ivSpan = MemoryMarshal.Cast<byte, uint>(iv);
		ivSpan.Slice(0, 4).CopyTo(state.Slice(12));

		ChaChaRound(state);

		state.Slice(12).CopyTo(state.Slice(8));
		state.Slice(0, 4).CopyTo(state.Slice(4));

		sigma.CopyTo(state);

		state[14] = ivSpan[4];
		state[15] = ivSpan[5];
	}
}
