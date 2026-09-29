namespace CryptoBase.Ciphers.Blocks.Aes;

internal readonly ref struct AesOutputMaskPolicy : IAesModePolicy
{
	private readonly ref byte _xorOperand;

	internal AesOutputMaskPolicy(ReadOnlySpan<byte> xorOperand)
	{
		_xorOperand = ref xorOperand.GetReference();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal Vector128<byte> Xor(Vector128<byte> value, nuint offset)
	{
		return value ^ Vector128.LoadUnsafe(ref _xorOperand, offset);
	}

	public static bool UseBatch8 => true;

	public void Initialize(Vector128<byte> state, int length)
	{
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare8(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3, out Vector128<byte> v4, out Vector128<byte> v5, out Vector128<byte> v6, out Vector128<byte> v7)
	{
		default(AesDirectPolicy).Prepare8(ref source, offset, out v0, out v1, out v2, out v3, out v4, out v5, out v6, out v7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish8(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1, Vector128<byte> v2, Vector128<byte> v3, Vector128<byte> v4, Vector128<byte> v5, Vector128<byte> v6, Vector128<byte> v7)
	{
		BlockXor.XorStore8(ref _xorOperand, ref destination, offset, ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare4(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3)
	{
		default(AesDirectPolicy).Prepare4(ref source, offset, out v0, out v1, out v2, out v3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish4(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1, Vector128<byte> v2, Vector128<byte> v3)
	{
		BlockXor.XorStore4(ref _xorOperand, ref destination, offset, ref v0, ref v1, ref v2, ref v3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare2(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1)
	{
		default(AesDirectPolicy).Prepare2(ref source, offset, out v0, out v1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish2(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1)
	{
		BlockXor.XorStore2(ref _xorOperand, ref destination, offset, ref v0, ref v1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public Vector128<byte> Prepare1(ref byte source, nuint offset)
	{
		return default(AesDirectPolicy).Prepare1(ref source, offset);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish1(ref byte source, ref byte destination, nuint offset, Vector128<byte> value)
	{
		BlockXor.XorStore1(ref _xorOperand, ref destination, offset, ref value);
	}

	public void SaveState(ref Vector128<byte> state)
	{
	}
}
