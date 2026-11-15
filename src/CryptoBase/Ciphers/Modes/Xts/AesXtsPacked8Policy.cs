using CryptoBase.Ciphers.Blocks.Aes;

namespace CryptoBase.Ciphers.Modes.Xts;

// Without AVX-512, 16 registers hold eight blocks only if their tweaks advance in pairs.
// The pairs live here because, without AVX2, the JIT keeps a struct with 256-bit fields in memory.
internal struct AesXtsPacked8Policy : IAesModePolicy
{
	private AesXtsPolicy _blocks;
	private Vector256<byte> _t01;
	private Vector256<byte> _t23;
	private Vector256<byte> _t45;
	private Vector256<byte> _t67;

	internal static bool IsSupported
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => !Avx512F.IsSupported && !AdvSimd.Arm64.IsSupported && Avx2.IsSupported && Pclmulqdq.V256.IsSupported;
	}

	public static bool UseBatch8 => true;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Initialize(Vector128<byte> tweak, int length)
	{
		_blocks.Initialize(tweak, length);

		if (length >= 128)
		{
			XtsTweak.CreatePacked8(tweak, out _t01, out _t23, out _t45, out _t67);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare8(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3, out Vector128<byte> v4, out Vector128<byte> v5, out Vector128<byte> v6, out Vector128<byte> v7)
	{
		v0 = Vector128.LoadUnsafe(ref source, offset) ^ _t01.GetLower();
		v1 = Vector128.LoadUnsafe(ref source, offset + 16) ^ _t01.GetUpper();
		v2 = Vector128.LoadUnsafe(ref source, offset + 32) ^ _t23.GetLower();
		v3 = Vector128.LoadUnsafe(ref source, offset + 48) ^ _t23.GetUpper();
		v4 = Vector128.LoadUnsafe(ref source, offset + 64) ^ _t45.GetLower();
		v5 = Vector128.LoadUnsafe(ref source, offset + 80) ^ _t45.GetUpper();
		v6 = Vector128.LoadUnsafe(ref source, offset + 96) ^ _t67.GetLower();
		v7 = Vector128.LoadUnsafe(ref source, offset + 112) ^ _t67.GetUpper();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish8(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1, Vector128<byte> v2, Vector128<byte> v3, Vector128<byte> v4, Vector128<byte> v5, Vector128<byte> v6, Vector128<byte> v7)
	{
		(Vector256.Create(v0, v1) ^ _t01).StoreUnsafe(ref destination, offset);
		(Vector256.Create(v2, v3) ^ _t23).StoreUnsafe(ref destination, offset + 32);
		(Vector256.Create(v4, v5) ^ _t45).StoreUnsafe(ref destination, offset + 64);
		(Vector256.Create(v6, v7) ^ _t67).StoreUnsafe(ref destination, offset + 96);

		XtsTweak.AdvancePacked8(ref _t01, ref _t23, ref _t45, ref _t67);
		_blocks.SetTweak(_t01.GetLower());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare4(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3)
	{
		_blocks.Prepare4(ref source, offset, out v0, out v1, out v2, out v3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish4(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1, Vector128<byte> v2, Vector128<byte> v3)
	{
		_blocks.Finish4(ref source, ref destination, offset, v0, v1, v2, v3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare2(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1)
	{
		_blocks.Prepare2(ref source, offset, out v0, out v1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish2(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1)
	{
		_blocks.Finish2(ref source, ref destination, offset, v0, v1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public Vector128<byte> Prepare1(ref byte source, nuint offset)
	{
		return _blocks.Prepare1(ref source, offset);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish1(ref byte source, ref byte destination, nuint offset, Vector128<byte> value)
	{
		_blocks.Finish1(ref source, ref destination, offset, value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly void SaveState(ref Vector128<byte> state)
	{
		_blocks.SaveState(ref state);
	}
}
