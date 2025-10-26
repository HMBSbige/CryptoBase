namespace CryptoBase.SymmetricCryptos.StreamCryptos.XChaCha20;

public abstract class XChaCha20Crypto : ChaCha20CryptoBase
{
	public override string Name => @"XChaCha20";

	public override int IvSize => 24;

	private readonly ReadOnlyMemory<byte> _key;

	protected XChaCha20Crypto(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, 32, nameof(key));

		_key = key.ToArray();

		SetIV(iv);
		Reset();
	}

	public sealed override void Reset()
	{
		SetCounter(0);
	}

	protected override void IncrementCounter(Span<uint> state)
	{
		ChaCha20Utils.IncrementCounterOriginal(state);
	}

	protected abstract void ChaChaRound(uint[] x);

	public void SetIV(ReadOnlySpan<byte> iv)
	{
		Span<uint> span = State.AsSpan(0, StateSize);
		Span<uint> sigma = Sigma32.AsSpan();

		sigma.CopyTo(span);

		ReadOnlySpan<uint> keySpan = MemoryMarshal.Cast<byte, uint>(_key.Span);
		keySpan.CopyTo(span.Slice(4));

		ReadOnlySpan<uint> ivSpan = MemoryMarshal.Cast<byte, uint>(iv);
		ivSpan.Slice(0, 4).CopyTo(span.Slice(12));

		ChaChaRound(State);

		span.Slice(12).CopyTo(span.Slice(8));
		span.Slice(0, 4).CopyTo(span.Slice(4));

		sigma.CopyTo(span);

		State[14] = ivSpan[4];
		State[15] = ivSpan[5];
	}

	public void SetCounter(ulong counter)
	{
		Index = 0;
		Unsafe.As<uint, ulong>(ref Unsafe.Add(ref MemoryMarshal.GetArrayDataReference(State), 12)) = counter;
	}
}
