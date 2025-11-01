namespace CryptoBase.SymmetricCryptos.StreamCryptos;

public class XChaCha20Crypto : ChaCha20OriginalCrypto
{
	public override string Name => @"XChaCha20";

	public override int IvSize => 24;

	public const int KeySize = 32;

	private readonly CryptoArrayPool<byte> _key = new(KeySize);

	public XChaCha20Crypto(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : base(key, iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeySize, nameof(key));

		key.CopyTo(_key.Span);

		SetIV(iv);
		SetCounter(0);
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

	public sealed override void SetIV(ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, IvSize, nameof(iv));

		Span<uint> state = State.Span;
		ReadOnlySpan<uint> sigma = Sigma32.AsSpan();
		ReadOnlySpan<uint> keySpan = MemoryMarshal.Cast<byte, uint>(_key.Span);
		ReadOnlySpan<uint> ivSpan = MemoryMarshal.Cast<byte, uint>(iv);

		sigma.CopyTo(state);
		keySpan.CopyTo(state.Slice(4));
		ivSpan.Slice(0, 4).CopyTo(state.Slice(12));

		ChaChaRound(state);

		state.Slice(12).CopyTo(state.Slice(8));
		state.Slice(0, 4).CopyTo(state.Slice(4));
		sigma.CopyTo(state);

		state[14] = ivSpan[4];
		state[15] = ivSpan[5];
	}

	public override void Dispose()
	{
		_key.Dispose();
		base.Dispose();
		GC.SuppressFinalize(this);
	}
}
