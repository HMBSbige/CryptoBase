namespace CryptoBase.SymmetricCryptos.StreamCryptos;

public abstract class Salsa20Crypto : SnuffleCrypto
{
	public override string Name => @"Salsa20";

	protected override void IncrementCounter()
	{
		ref uint counter = ref Unsafe.Add(ref MemoryMarshal.GetReference(State.AsSpan()), 8);
		if (++counter == 0)
		{
			++Unsafe.Add(ref MemoryMarshal.GetReference(State.AsSpan()), 9);
		}
	}
}
