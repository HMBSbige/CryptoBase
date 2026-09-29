namespace CryptoBase.Ciphers.Modes.Ctr;

// Lane state is little-endian; Next methods return big-endian counter blocks and advance it.
internal static class CtrLanes<TIncrementer> where TIncrementer : struct, ICtrIncrementer
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector256<byte> Create2(Vector128<byte> current)
	{
		return TIncrementer.Add01(Vector256.Create(current));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector512<byte> Create4(Vector128<byte> current)
	{
		return TIncrementer.Add0123(Vector512.Create(current));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> Next(ref Vector128<byte> current)
	{
		Vector128<byte> counter = current.ReverseEndianness128();
		current = TIncrementer.Inc(current);
		return counter;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector256<byte> Next2(ref Vector256<byte> lanes)
	{
		Vector256<byte> counters = lanes.ReverseEndianness128();
		lanes = TIncrementer.Add22(lanes);
		return counters;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector512<byte> Next4(ref Vector512<byte> lanes)
	{
		Vector512<byte> counters = lanes.ReverseEndianness128();
		lanes = TIncrementer.Add4444(lanes);
		return counters;
	}
}
