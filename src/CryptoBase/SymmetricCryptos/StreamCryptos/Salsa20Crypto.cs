namespace CryptoBase.SymmetricCryptos.StreamCryptos;

public abstract class Salsa20Crypto : SnuffleCrypto
{
	public override string Name => @"Salsa20";

	protected override void IncrementCounter(Span<uint> state)
	{
		++Unsafe.As<uint, ulong>(ref Unsafe.Add(ref MemoryMarshal.GetReference(state), 8));
	}
}
