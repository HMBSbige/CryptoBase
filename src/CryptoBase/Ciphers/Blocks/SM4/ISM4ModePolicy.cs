namespace CryptoBase.Ciphers.Blocks.SM4;

internal interface ISM4ModePolicy
{
	void Initialize(Vector128<byte> state);

	void Prepare8(ref byte source, nuint offset, out Vector256<byte> x0, out Vector256<byte> x1, out Vector256<byte> x2, out Vector256<byte> x3);
	void Finish8(ref byte source, ref byte destination, nuint offset, Vector256<byte> x0, Vector256<byte> x1, Vector256<byte> x2, Vector256<byte> x3);

	void Prepare16(ref byte source, nuint offset, out Vector512<byte> x0, out Vector512<byte> x1, out Vector512<byte> x2, out Vector512<byte> x3);
	void Finish16(ref byte source, ref byte destination, nuint offset, Vector512<byte> x0, Vector512<byte> x1, Vector512<byte> x2, Vector512<byte> x3);

	void SaveState(ref Vector128<byte> state);
}
