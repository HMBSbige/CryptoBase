using CryptoBase.Ciphers.Blocks.Aes;

namespace CryptoBase.Ciphers.Modes.Xts;

internal struct AesXtsPolicy : IAesModePolicy
{
	private Vector128<byte> _t0;
	private Vector128<byte> _t1;
	private Vector128<byte> _t2;
	private Vector128<byte> _t3;
	private Vector128<byte> _t4;
	private Vector128<byte> _t5;
	private Vector128<byte> _t6;
	private Vector128<byte> _t7;
	private Vector256<byte> _t01;
	private Vector256<byte> _t23;
	private Vector256<byte> _t45;
	private Vector256<byte> _t67;
	private Vector128<byte> _tweak;

	// Only 16 registers
	private static bool Packed8 => !Avx512F.IsSupported && !AdvSimd.Arm64.IsSupported && Avx2.IsSupported && Pclmulqdq.V256.IsSupported;

	public static bool UseBatch8 => Avx512F.IsSupported || AdvSimd.Arm64.IsSupported || Packed8;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Initialize(Vector128<byte> tweak, int length)
	{
		_tweak = tweak;

		if (Packed8 && length >= 128)
		{
			XtsTweak.CreatePacked8(tweak, out _t01, out _t23, out _t45, out _t67);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare8(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3, out Vector128<byte> v4, out Vector128<byte> v5, out Vector128<byte> v6, out Vector128<byte> v7)
	{
		if (Packed8)
		{
			v0 = Vector128.LoadUnsafe(ref source, offset) ^ _t01.GetLower();
			v1 = Vector128.LoadUnsafe(ref source, offset + 16) ^ _t01.GetUpper();
			v2 = Vector128.LoadUnsafe(ref source, offset + 32) ^ _t23.GetLower();
			v3 = Vector128.LoadUnsafe(ref source, offset + 48) ^ _t23.GetUpper();
			v4 = Vector128.LoadUnsafe(ref source, offset + 64) ^ _t45.GetLower();
			v5 = Vector128.LoadUnsafe(ref source, offset + 80) ^ _t45.GetUpper();
			v6 = Vector128.LoadUnsafe(ref source, offset + 96) ^ _t67.GetLower();
			v7 = Vector128.LoadUnsafe(ref source, offset + 112) ^ _t67.GetUpper();
			return;
		}

		_t0 = _tweak;
		_t1 = XtsTweak.MultiplyByAlpha(_t0);
		_t2 = XtsTweak.MultiplyByAlpha(_t1);
		_t3 = XtsTweak.MultiplyByAlpha(_t2);
		_t4 = XtsTweak.MultiplyByAlpha(_t3);
		_t5 = XtsTweak.MultiplyByAlpha(_t4);
		_t6 = XtsTweak.MultiplyByAlpha(_t5);
		_t7 = XtsTweak.MultiplyByAlpha(_t6);

		v0 = Vector128.LoadUnsafe(ref source, offset) ^ _t0;
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
		if (Packed8)
		{
			(Vector256.Create(v0, v1) ^ _t01).StoreUnsafe(ref destination, offset);
			(Vector256.Create(v2, v3) ^ _t23).StoreUnsafe(ref destination, offset + 32);
			(Vector256.Create(v4, v5) ^ _t45).StoreUnsafe(ref destination, offset + 64);
			(Vector256.Create(v6, v7) ^ _t67).StoreUnsafe(ref destination, offset + 96);

			XtsTweak.AdvancePacked8(ref _t01, ref _t23, ref _t45, ref _t67);
			_tweak = _t01.GetLower();
			return;
		}

		(v0 ^ _t0).StoreUnsafe(ref destination, offset);
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
		_t0 = _tweak;
		_t1 = XtsTweak.MultiplyByAlpha(_t0);
		_t2 = XtsTweak.MultiplyByAlpha(_t1);
		_t3 = XtsTweak.MultiplyByAlpha(_t2);

		v0 = Vector128.LoadUnsafe(ref source, offset) ^ _t0;
		v1 = Vector128.LoadUnsafe(ref source, offset + 16) ^ _t1;
		v2 = Vector128.LoadUnsafe(ref source, offset + 32) ^ _t2;
		v3 = Vector128.LoadUnsafe(ref source, offset + 48) ^ _t3;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish4(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1, Vector128<byte> v2, Vector128<byte> v3)
	{
		(v0 ^ _t0).StoreUnsafe(ref destination, offset);
		(v1 ^ _t1).StoreUnsafe(ref destination, offset + 16);
		(v2 ^ _t2).StoreUnsafe(ref destination, offset + 32);
		(v3 ^ _t3).StoreUnsafe(ref destination, offset + 48);
		_tweak = XtsTweak.MultiplyByAlpha(_t3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare2(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1)
	{
		_t0 = _tweak;
		_t1 = XtsTweak.MultiplyByAlpha(_t0);

		v0 = Vector128.LoadUnsafe(ref source, offset) ^ _t0;
		v1 = Vector128.LoadUnsafe(ref source, offset + 16) ^ _t1;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish2(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1)
	{
		(v0 ^ _t0).StoreUnsafe(ref destination, offset);
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
