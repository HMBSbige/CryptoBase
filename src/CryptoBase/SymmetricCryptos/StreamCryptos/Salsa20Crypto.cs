namespace CryptoBase.SymmetricCryptos.StreamCryptos;

public abstract class Salsa20Crypto : SnuffleCrypto
{
	public override string Name => @"Salsa20";

	protected override void IncrementCounter(Span<uint> state)
	{
		ref ulong counter = ref Unsafe.As<uint, ulong>(ref Unsafe.Add(ref MemoryMarshal.GetReference(state), 8));
		++counter;
	}
}
