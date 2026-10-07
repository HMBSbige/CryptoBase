namespace CryptoBase.Ciphers.Modes.Ccm;

// References keep calls cheap where shared generic code cannot inline them.
internal interface ICcmBlockEncryptor
{
	void Begin(ref Vector128<byte> state, ref Vector128<byte> counterBlock);

	void Absorb(ref Vector128<byte> state, Vector128<byte> block);

	void Absorb(ref Vector128<byte> state, Vector128<byte> block, ref Vector128<byte> counterBlock);

	Vector128<byte> Finish(Vector128<byte> state);
}
