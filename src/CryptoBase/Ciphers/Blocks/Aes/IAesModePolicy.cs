namespace CryptoBase.Ciphers.Blocks.Aes;

internal interface IAesModePolicy
{
	static abstract bool UseBatch8 { get; }

	void Initialize(Vector128<byte> state, int length);

	void Prepare8(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3, out Vector128<byte> v4, out Vector128<byte> v5, out Vector128<byte> v6, out Vector128<byte> v7);
	void Finish8(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1, Vector128<byte> v2, Vector128<byte> v3, Vector128<byte> v4, Vector128<byte> v5, Vector128<byte> v6, Vector128<byte> v7);

	void Prepare4(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3);
	void Finish4(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1, Vector128<byte> v2, Vector128<byte> v3);

	void Prepare2(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1);
	void Finish2(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1);

	Vector128<byte> Prepare1(ref byte source, nuint offset);
	void Finish1(ref byte source, ref byte destination, nuint offset, Vector128<byte> value);

	void SaveState(ref Vector128<byte> state);
}
