namespace CryptoBase.SymmetricCryptos.StreamCryptos;

public abstract class Salsa20Crypto : SnuffleCrypto
{
	public override string Name => @"Salsa20";

	protected override void IncrementCounter(Span<uint> state)
	{
		ref uint stateRef = ref state.GetReference();
		++Unsafe.As<uint, ulong>(ref Unsafe.Add(ref stateRef, 8));
	}
}
