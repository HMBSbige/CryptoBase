namespace CryptoBase.Ciphers.Modes.Ctr;

// The next big-endian counter block, and the keystream block whose bytes from Index on are still unused.
// KeyStream comes first so that a reference to the state and one to Counter differ; the JIT would otherwise merge the two in CtrMode128.Xor and spill the result.
internal struct CtrStreamState
{
	public Vector128<byte> KeyStream;
	public Vector128<byte> Counter;
	public int Index;
}
