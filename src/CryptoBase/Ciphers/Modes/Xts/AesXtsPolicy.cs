using CryptoBase.Ciphers.Blocks.Aes;

namespace CryptoBase.Ciphers.Modes.Xts;

internal struct AesXtsPolicy : IAesModePolicy
{
	private Vector128<byte> _t1;
	private Vector128<byte> _t2;
	private Vector128<byte> _t3;
	private Vector128<byte> _t4;
	private Vector128<byte> _t5;
	private Vector128<byte> _t6;
	private Vector128<byte> _t7;
	private Vector128<byte> _tweak;

	// With 16 registers, AesXtsPacked8Policy batches eight blocks instead.
	public static bool UseBatch8 => Avx512F.IsSupported || AdvSimd.Arm64.IsSupported;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal void SetTweak(Vector128<byte> tweak)
	{
		_tweak = tweak;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Initialize(Vector128<byte> tweak, int length)
	{
		_tweak = tweak;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare8(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3, out Vector128<byte> v4, out Vector128<byte> v5, out Vector128<byte> v6, out Vector128<byte> v7)
	{
		_t1 = XtsTweak.MultiplyByAlpha(_tweak);
		_t2 = XtsTweak.MultiplyByAlpha(_t1);
		_t3 = XtsTweak.MultiplyByAlpha(_t2);
		_t4 = XtsTweak.MultiplyByAlpha(_t3);
		_t5 = XtsTweak.MultiplyByAlpha(_t4);
		_t6 = XtsTweak.MultiplyByAlpha(_t5);
		_t7 = XtsTweak.MultiplyByAlpha(_t6);

		v0 = Vector128.LoadUnsafe(ref source, offset) ^ _tweak;
		v1 = Vector128.LoadUnsafe(ref source, offset + 16) ^ _t1;
		v2 = Vector128.LoadUnsafe(ref source, offset + 32) ^ _t2;
		v3 = Vector128.LoadUnsafe(ref source, offset + 48) ^ _t3;
		v4 = Vector128.LoadUnsafe(ref source, offset + 64) ^ _t4;
		v5 = Vector128.LoadUnsafe(ref source, offset + 80) ^ _t5;
		v6 = Vector128.LoadUnsafe(ref source, offset + 96) ^ _t6;
		v7 = Vector128.LoadUnsafe(ref source, offset + 112) ^ _t7;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish8(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1, Vector128<byte> v2, Vector128<byte> v3, Vector128<byte> v4, Vector128<byte> v5, Vector128<byte> v6, Vector128<byte> v7)
	{
		(v0 ^ _tweak).StoreUnsafe(ref destination, offset);
		(v1 ^ _t1).StoreUnsafe(ref destination, offset + 16);
		(v2 ^ _t2).StoreUnsafe(ref destination, offset + 32);
		(v3 ^ _t3).StoreUnsafe(ref destination, offset + 48);
		(v4 ^ _t4).StoreUnsafe(ref destination, offset + 64);
		(v5 ^ _t5).StoreUnsafe(ref destination, offset + 80);
		(v6 ^ _t6).StoreUnsafe(ref destination, offset + 96);
		(v7 ^ _t7).StoreUnsafe(ref destination, offset + 112);
		_tweak = XtsTweak.MultiplyByAlpha(_t7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare4(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3)
	{
		_t1 = XtsTweak.MultiplyByAlpha(_tweak);
		_t2 = XtsTweak.MultiplyByAlpha(_t1);
		_t3 = XtsTweak.MultiplyByAlpha(_t2);

		v0 = Vector128.LoadUnsafe(ref source, offset) ^ _tweak;
		v1 = Vector128.LoadUnsafe(ref source, offset + 16) ^ _t1;
		v2 = Vector128.LoadUnsafe(ref source, offset + 32) ^ _t2;
		v3 = Vector128.LoadUnsafe(ref source, offset + 48) ^ _t3;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish4(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1, Vector128<byte> v2, Vector128<byte> v3)
	{
		(v0 ^ _tweak).StoreUnsafe(ref destination, offset);
		(v1 ^ _t1).StoreUnsafe(ref destination, offset + 16);
		(v2 ^ _t2).StoreUnsafe(ref destination, offset + 32);
		(v3 ^ _t3).StoreUnsafe(ref destination, offset + 48);
		_tweak = XtsTweak.MultiplyByAlpha(_t3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare2(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1)
	{
		_t1 = XtsTweak.MultiplyByAlpha(_tweak);

		v0 = Vector128.LoadUnsafe(ref source, offset) ^ _tweak;
		v1 = Vector128.LoadUnsafe(ref source, offset + 16) ^ _t1;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish2(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1)
	{
		(v0 ^ _tweak).StoreUnsafe(ref destination, offset);
		(v1 ^ _t1).StoreUnsafe(ref destination, offset + 16);
		_tweak = XtsTweak.MultiplyByAlpha(_t1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public Vector128<byte> Prepare1(ref byte source, nuint offset)
	{
		return Vector128.LoadUnsafe(ref source, offset) ^ _tweak;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish1(ref byte source, ref byte destination, nuint offset, Vector128<byte> value)
	{
		(value ^ _tweak).StoreUnsafe(ref destination, offset);
		_tweak = XtsTweak.MultiplyByAlpha(_tweak);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly void SaveState(ref Vector128<byte> state)
	{
		state = _tweak;
	}
}
