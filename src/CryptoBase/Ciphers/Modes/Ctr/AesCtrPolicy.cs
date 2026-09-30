using CryptoBase.Ciphers.Blocks.Aes;

namespace CryptoBase.Ciphers.Modes.Ctr;

internal struct AesCtrPolicy<TIncrementer> : IAesModePolicy where TIncrementer : struct, ICtrIncrementer
{
	private Vector128<byte> _current;
	private Vector256<byte> _lanes256;
	private Vector512<byte> _lanes512;

	public static bool UseBatch8 => true;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Initialize(Vector128<byte> counter, int length)
	{
		_current = counter.ReverseEndianness128();

		if (length >= 64)
		{
			if (Avx512BW.IsSupported)
			{
				_lanes512 = CtrLanes<TIncrementer>.Create4(_current);
			}
			else if (Avx2.IsSupported)
			{
				_lanes256 = CtrLanes<TIncrementer>.Create2(_current);
			}
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare8(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3, out Vector128<byte> v4, out Vector128<byte> v5, out Vector128<byte> v6, out Vector128<byte> v7)
	{
		if (Avx512BW.IsSupported)
		{
			Next4(ref _lanes512, out v0, out v1, out v2, out v3);
			Next4(ref _lanes512, out v4, out v5, out v6, out v7);
			_current = _lanes512.GetLower().GetLower();
		}
		else if (Avx2.IsSupported)
		{
			Next2(ref _lanes256, out v0, out v1);
			Next2(ref _lanes256, out v2, out v3);
			Next2(ref _lanes256, out v4, out v5);
			Next2(ref _lanes256, out v6, out v7);
			_current = _lanes256.GetLower();
		}
		else
		{
			v0 = CtrLanes<TIncrementer>.Next(ref _current);
			v1 = CtrLanes<TIncrementer>.Next(ref _current);
			v2 = CtrLanes<TIncrementer>.Next(ref _current);
			v3 = CtrLanes<TIncrementer>.Next(ref _current);
			v4 = CtrLanes<TIncrementer>.Next(ref _current);
			v5 = CtrLanes<TIncrementer>.Next(ref _current);
			v6 = CtrLanes<TIncrementer>.Next(ref _current);
			v7 = CtrLanes<TIncrementer>.Next(ref _current);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly void Finish8(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1, Vector128<byte> v2, Vector128<byte> v3, Vector128<byte> v4, Vector128<byte> v5, Vector128<byte> v6, Vector128<byte> v7)
	{
		BlockXor.XorStore8(ref source, ref destination, offset, ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare4(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3)
	{
		if (Avx512BW.IsSupported)
		{
			Next4(ref _lanes512, out v0, out v1, out v2, out v3);
			_current = _lanes512.GetLower().GetLower();
		}
		else if (Avx2.IsSupported)
		{
			Next2(ref _lanes256, out v0, out v1);
			Next2(ref _lanes256, out v2, out v3);
			_current = _lanes256.GetLower();
		}
		else
		{
			v0 = CtrLanes<TIncrementer>.Next(ref _current);
			v1 = CtrLanes<TIncrementer>.Next(ref _current);
			v2 = CtrLanes<TIncrementer>.Next(ref _current);
			v3 = CtrLanes<TIncrementer>.Next(ref _current);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly void Finish4(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1, Vector128<byte> v2, Vector128<byte> v3)
	{
		BlockXor.XorStore4(ref source, ref destination, offset, ref v0, ref v1, ref v2, ref v3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare2(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1)
	{
		v0 = CtrLanes<TIncrementer>.Next(ref _current);
		v1 = CtrLanes<TIncrementer>.Next(ref _current);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly void Finish2(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1)
	{
		BlockXor.XorStore2(ref source, ref destination, offset, ref v0, ref v1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public Vector128<byte> Prepare1(ref byte source, nuint offset)
	{
		return CtrLanes<TIncrementer>.Next(ref _current);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly void Finish1(ref byte source, ref byte destination, nuint offset, Vector128<byte> value)
	{
		BlockXor.XorStore1(ref source, ref destination, offset, ref value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly void SaveState(ref Vector128<byte> state)
	{
		state = _current.ReverseEndianness128();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Next2(ref Vector256<byte> lanes, out Vector128<byte> v0, out Vector128<byte> v1)
	{
		Vector256<byte> counters = CtrLanes<TIncrementer>.Next2(ref lanes);
		v0 = counters.GetLower();
		v1 = counters.GetUpper();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Next4(ref Vector512<byte> lanes, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3)
	{
		Vector512<byte> counters = CtrLanes<TIncrementer>.Next4(ref lanes);
		v0 = counters.GetLower().GetLower();
		v1 = counters.GetLower().GetUpper();
		v2 = counters.GetUpper().GetLower();
		v3 = counters.GetUpper().GetUpper();
	}
}
