namespace CryptoBase.Ciphers.Blocks.Aes;

internal readonly ref struct AesInputOutputMaskPolicy : IAesModePolicy
{
	private readonly AesOutputMaskPolicy _outputMask;

	internal AesInputOutputMaskPolicy(ReadOnlySpan<byte> xorOperand)
	{
		_outputMask = new AesOutputMaskPolicy(xorOperand);
	}

	public static bool UseBatch8 => true;

	public void Initialize(Vector128<byte> state, int length)
	{
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare8(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3, out Vector128<byte> v4, out Vector128<byte> v5, out Vector128<byte> v6, out Vector128<byte> v7)
	{
		_outputMask.Prepare8(ref source, offset, out v0, out v1, out v2, out v3, out v4, out v5, out v6, out v7);
		v0 = _outputMask.Xor(v0, offset);
		v1 = _outputMask.Xor(v1, offset + 16);
		v2 = _outputMask.Xor(v2, offset + 32);
		v3 = _outputMask.Xor(v3, offset + 48);
		v4 = _outputMask.Xor(v4, offset + 64);
		v5 = _outputMask.Xor(v5, offset + 80);
		v6 = _outputMask.Xor(v6, offset + 96);
		v7 = _outputMask.Xor(v7, offset + 112);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish8(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1, Vector128<byte> v2, Vector128<byte> v3, Vector128<byte> v4, Vector128<byte> v5, Vector128<byte> v6, Vector128<byte> v7)
	{
		_outputMask.Finish8(ref source, ref destination, offset, v0, v1, v2, v3, v4, v5, v6, v7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare4(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3)
	{
		_outputMask.Prepare4(ref source, offset, out v0, out v1, out v2, out v3);
		v0 = _outputMask.Xor(v0, offset);
		v1 = _outputMask.Xor(v1, offset + 16);
		v2 = _outputMask.Xor(v2, offset + 32);
		v3 = _outputMask.Xor(v3, offset + 48);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish4(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1, Vector128<byte> v2, Vector128<byte> v3)
	{
		_outputMask.Finish4(ref source, ref destination, offset, v0, v1, v2, v3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare2(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1)
	{
		_outputMask.Prepare2(ref source, offset, out v0, out v1);
		v0 = _outputMask.Xor(v0, offset);
		v1 = _outputMask.Xor(v1, offset + 16);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish2(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1)
	{
		_outputMask.Finish2(ref source, ref destination, offset, v0, v1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public Vector128<byte> Prepare1(ref byte source, nuint offset)
	{
		return _outputMask.Xor(_outputMask.Prepare1(ref source, offset), offset);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish1(ref byte source, ref byte destination, nuint offset, Vector128<byte> value)
	{
		_outputMask.Finish1(ref source, ref destination, offset, value);
	}

	public void SaveState(ref Vector128<byte> state)
	{
	}
}
