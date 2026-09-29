namespace CryptoBase.Ciphers.Blocks.Aes;

internal readonly struct AesDirectPolicy : IAesModePolicy
{
	public static bool UseBatch8 => true;

	public void Initialize(Vector128<byte> state, int length)
	{
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare8(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3, out Vector128<byte> v4, out Vector128<byte> v5, out Vector128<byte> v6, out Vector128<byte> v7)
	{
		ref byte current = ref Unsafe.Add(ref source, offset);
		v0 = Vector128.LoadUnsafe(ref current, 0);
		v1 = Vector128.LoadUnsafe(ref current, 16);
		v2 = Vector128.LoadUnsafe(ref current, 32);
		v3 = Vector128.LoadUnsafe(ref current, 48);
		v4 = Vector128.LoadUnsafe(ref current, 64);
		v5 = Vector128.LoadUnsafe(ref current, 80);
		v6 = Vector128.LoadUnsafe(ref current, 96);
		v7 = Vector128.LoadUnsafe(ref current, 112);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish8(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1, Vector128<byte> v2, Vector128<byte> v3, Vector128<byte> v4, Vector128<byte> v5, Vector128<byte> v6, Vector128<byte> v7)
	{
		ref byte current = ref Unsafe.Add(ref destination, offset);
		v0.StoreUnsafe(ref current, 0);
		v1.StoreUnsafe(ref current, 16);
		v2.StoreUnsafe(ref current, 32);
		v3.StoreUnsafe(ref current, 48);
		v4.StoreUnsafe(ref current, 64);
		v5.StoreUnsafe(ref current, 80);
		v6.StoreUnsafe(ref current, 96);
		v7.StoreUnsafe(ref current, 112);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare4(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3)
	{
		ref byte current = ref Unsafe.Add(ref source, offset);
		v0 = Vector128.LoadUnsafe(ref current, 0);
		v1 = Vector128.LoadUnsafe(ref current, 16);
		v2 = Vector128.LoadUnsafe(ref current, 32);
		v3 = Vector128.LoadUnsafe(ref current, 48);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish4(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1, Vector128<byte> v2, Vector128<byte> v3)
	{
		ref byte current = ref Unsafe.Add(ref destination, offset);
		v0.StoreUnsafe(ref current, 0);
		v1.StoreUnsafe(ref current, 16);
		v2.StoreUnsafe(ref current, 32);
		v3.StoreUnsafe(ref current, 48);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare2(ref byte source, nuint offset, out Vector128<byte> v0, out Vector128<byte> v1)
	{
		ref byte current = ref Unsafe.Add(ref source, offset);
		v0 = Vector128.LoadUnsafe(ref current, 0);
		v1 = Vector128.LoadUnsafe(ref current, 16);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish2(ref byte source, ref byte destination, nuint offset, Vector128<byte> v0, Vector128<byte> v1)
	{
		ref byte current = ref Unsafe.Add(ref destination, offset);
		v0.StoreUnsafe(ref current, 0);
		v1.StoreUnsafe(ref current, 16);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public Vector128<byte> Prepare1(ref byte source, nuint offset)
	{
		return Vector128.LoadUnsafe(ref source, offset);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish1(ref byte source, ref byte destination, nuint offset, Vector128<byte> value)
	{
		value.StoreUnsafe(ref destination, offset);
	}

	public void SaveState(ref Vector128<byte> state)
	{
	}
}
