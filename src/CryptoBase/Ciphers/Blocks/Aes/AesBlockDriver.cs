namespace CryptoBase.Ciphers.Blocks.Aes;

internal static class AesBlockDriver<TCore> where TCore : struct, IAesVectorCore
{
	internal static void EncryptBlocks(ref TCore core, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ref byte src = ref source.GetReference();
		ref byte dst = ref destination.GetReference();
		int offset = 0;

		while (source.Length - offset >= 128)
		{
			Encrypt8(ref core, ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset));
			offset += 128;
		}

		while (source.Length - offset >= 64)
		{
			Encrypt4(ref core, ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset));
			offset += 64;
		}

		while (source.Length - offset >= 32)
		{
			Encrypt2(ref core, ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset));
			offset += 32;
		}

		if (offset < source.Length)
		{
			core.Encrypt(Vector128.LoadUnsafe(ref src, (nuint)offset)).StoreUnsafe(ref dst, (nuint)offset);
		}
	}

	internal static void DecryptBlocks(ref TCore core, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ref byte src = ref source.GetReference();
		ref byte dst = ref destination.GetReference();
		int offset = 0;

		while (source.Length - offset >= 128)
		{
			Decrypt8(ref core, ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset));
			offset += 128;
		}

		while (source.Length - offset >= 64)
		{
			Decrypt4(ref core, ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset));
			offset += 64;
		}

		while (source.Length - offset >= 32)
		{
			Decrypt2(ref core, ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset));
			offset += 32;
		}

		if (offset < source.Length)
		{
			core.Decrypt(Vector128.LoadUnsafe(ref src, (nuint)offset)).StoreUnsafe(ref dst, (nuint)offset);
		}
	}

	internal static void TransformWithMask(ref TCore core, ReadOnlySpan<byte> source, ReadOnlySpan<byte> mask, Span<byte> destination, bool decrypt, bool xorInput)
	{
		ref byte src = ref source.GetReference();
		ref byte xor = ref mask.GetReference();
		ref byte dst = ref destination.GetReference();
		int offset = 0;

		for (; offset <= source.Length - 128; offset += 128)
		{
			Vector128<byte> v0 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 0));
			Vector128<byte> v1 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 16));
			Vector128<byte> v2 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 32));
			Vector128<byte> v3 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 48));
			Vector128<byte> v4 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 64));
			Vector128<byte> v5 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 80));
			Vector128<byte> v6 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 96));
			Vector128<byte> v7 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 112));

			if (xorInput)
			{
				v0 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 0));
				v1 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 16));
				v2 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 32));
				v3 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 48));
				v4 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 64));
				v5 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 80));
				v6 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 96));
				v7 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 112));
			}

			if (decrypt)
			{
				core.Decrypt8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
			}
			else
			{
				core.Encrypt8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
			}

			(v0 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 0))).StoreUnsafe(ref dst, (nuint)(offset + 0));
			(v1 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 16))).StoreUnsafe(ref dst, (nuint)(offset + 16));
			(v2 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 32))).StoreUnsafe(ref dst, (nuint)(offset + 32));
			(v3 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 48))).StoreUnsafe(ref dst, (nuint)(offset + 48));
			(v4 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 64))).StoreUnsafe(ref dst, (nuint)(offset + 64));
			(v5 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 80))).StoreUnsafe(ref dst, (nuint)(offset + 80));
			(v6 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 96))).StoreUnsafe(ref dst, (nuint)(offset + 96));
			(v7 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 112))).StoreUnsafe(ref dst, (nuint)(offset + 112));
		}

		if (offset == source.Length)
		{
			return;
		}

		if (offset <= source.Length - 64)
		{
			Vector128<byte> v0 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 0));
			Vector128<byte> v1 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 16));
			Vector128<byte> v2 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 32));
			Vector128<byte> v3 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 48));

			if (xorInput)
			{
				v0 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 0));
				v1 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 16));
				v2 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 32));
				v3 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 48));
			}

			if (decrypt)
			{
				core.Decrypt4(ref v0, ref v1, ref v2, ref v3);
			}
			else
			{
				core.Encrypt4(ref v0, ref v1, ref v2, ref v3);
			}

			(v0 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 0))).StoreUnsafe(ref dst, (nuint)(offset + 0));
			(v1 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 16))).StoreUnsafe(ref dst, (nuint)(offset + 16));
			(v2 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 32))).StoreUnsafe(ref dst, (nuint)(offset + 32));
			(v3 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 48))).StoreUnsafe(ref dst, (nuint)(offset + 48));
			offset += 64;
		}

		if (offset <= source.Length - 32)
		{
			Vector128<byte> v0 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 0));
			Vector128<byte> v1 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 16));

			if (xorInput)
			{
				v0 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 0));
				v1 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 16));
			}

			if (decrypt)
			{
				core.Decrypt2(ref v0, ref v1);
			}
			else
			{
				core.Encrypt2(ref v0, ref v1);
			}

			(v0 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 0))).StoreUnsafe(ref dst, (nuint)(offset + 0));
			(v1 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 16))).StoreUnsafe(ref dst, (nuint)(offset + 16));
			offset += 32;
		}

		if (offset < source.Length)
		{
			Vector128<byte> value = Vector128.LoadUnsafe(ref src, (nuint)offset);
			Vector128<byte> blockMask = Vector128.LoadUnsafe(ref xor, (nuint)offset);

			if (xorInput)
			{
				value ^= blockMask;
			}

			value = decrypt ? core.Decrypt(value) : core.Encrypt(value);
			(value ^ blockMask).StoreUnsafe(ref dst, (nuint)offset);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Encrypt2(ref TCore core, ref byte source, ref byte destination)
	{
		Vector128<byte> v0 = Vector128.LoadUnsafe(ref source, 0);
		Vector128<byte> v1 = Vector128.LoadUnsafe(ref source, 16);
		core.Encrypt2(ref v0, ref v1);
		v0.StoreUnsafe(ref destination, 0);
		v1.StoreUnsafe(ref destination, 16);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Encrypt4(ref TCore core, ref byte source, ref byte destination)
	{
		Vector128<byte> v0 = Vector128.LoadUnsafe(ref source, 0);
		Vector128<byte> v1 = Vector128.LoadUnsafe(ref source, 16);
		Vector128<byte> v2 = Vector128.LoadUnsafe(ref source, 32);
		Vector128<byte> v3 = Vector128.LoadUnsafe(ref source, 48);
		core.Encrypt4(ref v0, ref v1, ref v2, ref v3);
		v0.StoreUnsafe(ref destination, 0);
		v1.StoreUnsafe(ref destination, 16);
		v2.StoreUnsafe(ref destination, 32);
		v3.StoreUnsafe(ref destination, 48);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Encrypt8(ref TCore core, ref byte source, ref byte destination)
	{
		Vector128<byte> v0 = Vector128.LoadUnsafe(ref source, 0);
		Vector128<byte> v1 = Vector128.LoadUnsafe(ref source, 16);
		Vector128<byte> v2 = Vector128.LoadUnsafe(ref source, 32);
		Vector128<byte> v3 = Vector128.LoadUnsafe(ref source, 48);
		Vector128<byte> v4 = Vector128.LoadUnsafe(ref source, 64);
		Vector128<byte> v5 = Vector128.LoadUnsafe(ref source, 80);
		Vector128<byte> v6 = Vector128.LoadUnsafe(ref source, 96);
		Vector128<byte> v7 = Vector128.LoadUnsafe(ref source, 112);
		core.Encrypt8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
		v0.StoreUnsafe(ref destination, 0);
		v1.StoreUnsafe(ref destination, 16);
		v2.StoreUnsafe(ref destination, 32);
		v3.StoreUnsafe(ref destination, 48);
		v4.StoreUnsafe(ref destination, 64);
		v5.StoreUnsafe(ref destination, 80);
		v6.StoreUnsafe(ref destination, 96);
		v7.StoreUnsafe(ref destination, 112);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Decrypt2(ref TCore core, ref byte source, ref byte destination)
	{
		Vector128<byte> v0 = Vector128.LoadUnsafe(ref source, 0);
		Vector128<byte> v1 = Vector128.LoadUnsafe(ref source, 16);
		core.Decrypt2(ref v0, ref v1);
		v0.StoreUnsafe(ref destination, 0);
		v1.StoreUnsafe(ref destination, 16);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Decrypt4(ref TCore core, ref byte source, ref byte destination)
	{
		Vector128<byte> v0 = Vector128.LoadUnsafe(ref source, 0);
		Vector128<byte> v1 = Vector128.LoadUnsafe(ref source, 16);
		Vector128<byte> v2 = Vector128.LoadUnsafe(ref source, 32);
		Vector128<byte> v3 = Vector128.LoadUnsafe(ref source, 48);
		core.Decrypt4(ref v0, ref v1, ref v2, ref v3);
		v0.StoreUnsafe(ref destination, 0);
		v1.StoreUnsafe(ref destination, 16);
		v2.StoreUnsafe(ref destination, 32);
		v3.StoreUnsafe(ref destination, 48);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Decrypt8(ref TCore core, ref byte source, ref byte destination)
	{
		Vector128<byte> v0 = Vector128.LoadUnsafe(ref source, 0);
		Vector128<byte> v1 = Vector128.LoadUnsafe(ref source, 16);
		Vector128<byte> v2 = Vector128.LoadUnsafe(ref source, 32);
		Vector128<byte> v3 = Vector128.LoadUnsafe(ref source, 48);
		Vector128<byte> v4 = Vector128.LoadUnsafe(ref source, 64);
		Vector128<byte> v5 = Vector128.LoadUnsafe(ref source, 80);
		Vector128<byte> v6 = Vector128.LoadUnsafe(ref source, 96);
		Vector128<byte> v7 = Vector128.LoadUnsafe(ref source, 112);
		core.Decrypt8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
		v0.StoreUnsafe(ref destination, 0);
		v1.StoreUnsafe(ref destination, 16);
		v2.StoreUnsafe(ref destination, 32);
		v3.StoreUnsafe(ref destination, 48);
		v4.StoreUnsafe(ref destination, 64);
		v5.StoreUnsafe(ref destination, 80);
		v6.StoreUnsafe(ref destination, 96);
		v7.StoreUnsafe(ref destination, 112);
	}
}
