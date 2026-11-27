using CryptoBase.Ciphers.Modes;

namespace CryptoBase.Ciphers.Blocks.Aes;

internal static class AesBlockDriver<TCore> where TCore : struct, IAesVectorCore
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void TransformShort<TDirection>(ref TCore core, ReadOnlySpan<byte> source, Span<byte> destination) where TDirection : struct, IBlockDirection
	{
		ref byte src = ref MemoryMarshal.GetReference(source);
		ref byte dst = ref MemoryMarshal.GetReference(destination);
		int length = source.Length;

		if (length <= 32)
		{
			if (length == 16)
			{
				Transform1<TDirection>(ref core, ref src, ref dst, 0);
			}
			else if (length == 32)
			{
				Transform2<TDirection>(ref core, ref src, ref dst, 0);
			}

			return;
		}

		if (length == 64)
		{
			Transform4<TDirection>(ref core, ref src, ref dst, 0);
			return;
		}

		TransformTail<TDirection>(ref core, ref src, ref dst, length);
	}

	// Taking the buffers as references and a length keeps every argument in a register on both x64 ABIs, so the entry tail-calls this loop.
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void TransformBatches<TDirection>(ref TCore core, ref byte src, ref byte dst, int remaining) where TDirection : struct, IBlockDirection
	{
		Debug.Assert(remaining >= 128);
		AesDirectPolicy policy = default;
		do
		{
			policy.Prepare8(ref src, 0, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3, out Vector128<byte> v4, out Vector128<byte> v5, out Vector128<byte> v6, out Vector128<byte> v7);
			if (TDirection.IsDecrypt)
			{
				core.Decrypt8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
			}
			else
			{
				core.Encrypt8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
			}

			policy.Finish8(ref src, ref dst, 0, v0, v1, v2, v3, v4, v5, v6, v7);
			src = ref Unsafe.Add(ref src, 128);
			dst = ref Unsafe.Add(ref dst, 128);
			remaining -= 128;
		}
		while (remaining >= 128);

		if (remaining != 0)
		{
			TransformTail<TDirection>(ref core, ref src, ref dst, remaining);
		}
	}

	// Keep the AES rounds for mixed batch widths together when tiered callers inline the public entry.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void TransformTail<TDirection>(ref TCore core, ref byte src, ref byte dst, int length) where TDirection : struct, IBlockDirection
	{
		nuint offset = 0;
		if ((length & 64) != 0)
		{
			Transform4<TDirection>(ref core, ref src, ref dst, 0);
			offset = 64;
		}

		if ((length & 32) != 0)
		{
			Transform2<TDirection>(ref core, ref src, ref dst, offset);
			offset += 32;
		}

		if ((length & 16) != 0)
		{
			Transform1<TDirection>(ref core, ref src, ref dst, offset);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Transform1<TDirection>(ref TCore core, ref byte src, ref byte dst, nuint offset) where TDirection : struct, IBlockDirection
	{
		if (TDirection.IsDecrypt)
		{
			core.Decrypt(Vector128.LoadUnsafe(ref src, offset)).StoreUnsafe(ref dst, offset);
		}
		else
		{
			core.Encrypt(Vector128.LoadUnsafe(ref src, offset)).StoreUnsafe(ref dst, offset);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Transform2<TDirection>(ref TCore core, ref byte src, ref byte dst, nuint offset) where TDirection : struct, IBlockDirection
	{
		Vector128<byte> v0 = Vector128.LoadUnsafe(ref src, offset);
		Vector128<byte> v1 = Vector128.LoadUnsafe(ref src, offset + 16);

		if (TDirection.IsDecrypt)
		{
			core.Decrypt2(ref v0, ref v1);
		}
		else
		{
			core.Encrypt2(ref v0, ref v1);
		}

		v0.StoreUnsafe(ref dst, offset);
		v1.StoreUnsafe(ref dst, offset + 16);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Transform4<TDirection>(ref TCore core, ref byte src, ref byte dst, nuint offset) where TDirection : struct, IBlockDirection
	{
		Vector128<byte> v0 = Vector128.LoadUnsafe(ref src, offset);
		Vector128<byte> v1 = Vector128.LoadUnsafe(ref src, offset + 16);
		Vector128<byte> v2 = Vector128.LoadUnsafe(ref src, offset + 32);
		Vector128<byte> v3 = Vector128.LoadUnsafe(ref src, offset + 48);

		if (TDirection.IsDecrypt)
		{
			core.Decrypt4(ref v0, ref v1, ref v2, ref v3);
		}
		else
		{
			core.Encrypt4(ref v0, ref v1, ref v2, ref v3);
		}

		v0.StoreUnsafe(ref dst, offset);
		v1.StoreUnsafe(ref dst, offset + 16);
		v2.StoreUnsafe(ref dst, offset + 32);
		v3.StoreUnsafe(ref dst, offset + 48);
	}

	// Keeps the ARM branch of AesCipher.EncryptBlocks to one call, because callers that inline that method pay inline budget for the IL of every branch.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void TransformBlocks<TDirection>(ref TCore core, ReadOnlySpan<byte> source, Span<byte> destination) where TDirection : struct, IBlockDirection
	{
		if (source.Length >= 128)
		{
			TransformBatches<TDirection>(ref core, ref MemoryMarshal.GetReference(source), ref MemoryMarshal.GetReference(destination), source.Length);
			return;
		}

		TransformShort<TDirection>(ref core, source, destination);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void TransformWithPolicy<TPolicy, TDirection>(ref TCore core, ref TPolicy policy, ReadOnlySpan<byte> source, Span<byte> destination) where TPolicy : struct, IAesModePolicy, allows ref struct where TDirection : struct, IBlockDirection
	{
		Process<TPolicy, TDirection>(ref core, ref policy, source, destination);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void Transform<TPolicy, TDirection>(ref TCore core, ref Vector128<byte> state, ReadOnlySpan<byte> source, Span<byte> destination) where TPolicy : struct, IAesModePolicy where TDirection : struct, IBlockDirection
	{
		Debug.Assert(source.Length % 16 is 0 && destination.Length >= source.Length);
		TPolicy policy = default;
		policy.Initialize(state, source.Length);
		Process<TPolicy, TDirection>(ref core, ref policy, source, destination);
		policy.SaveState(ref state);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Process<TPolicy, TDirection>(ref TCore core, ref TPolicy policy, ReadOnlySpan<byte> source, Span<byte> destination) where TPolicy : struct, IAesModePolicy, allows ref struct where TDirection : struct, IBlockDirection
	{
		ref byte src = ref MemoryMarshal.GetReference(source);
		ref byte dst = ref MemoryMarshal.GetReference(destination);
		int offset = 0;

		if (TPolicy.UseBatch8)
		{
			while (offset <= source.Length - 128)
			{
				nuint position = (nuint)offset;
				policy.Prepare8(ref src, position, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3, out Vector128<byte> v4, out Vector128<byte> v5, out Vector128<byte> v6, out Vector128<byte> v7);

				if (TDirection.IsDecrypt)
				{
					core.Decrypt8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
				}
				else
				{
					core.Encrypt8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
				}

				policy.Finish8(ref src, ref dst, position, v0, v1, v2, v3, v4, v5, v6, v7);
				offset += 128;
			}
		}

		while (offset <= source.Length - 64)
		{
			nuint position = (nuint)offset;
			policy.Prepare4(ref src, position, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3);

			if (TDirection.IsDecrypt)
			{
				core.Decrypt4(ref v0, ref v1, ref v2, ref v3);
			}
			else
			{
				core.Encrypt4(ref v0, ref v1, ref v2, ref v3);
			}

			policy.Finish4(ref src, ref dst, position, v0, v1, v2, v3);
			offset += 64;
		}

		if (offset <= source.Length - 32)
		{
			nuint position = (nuint)offset;
			policy.Prepare2(ref src, position, out Vector128<byte> v0, out Vector128<byte> v1);

			if (TDirection.IsDecrypt)
			{
				core.Decrypt2(ref v0, ref v1);
			}
			else
			{
				core.Encrypt2(ref v0, ref v1);
			}

			policy.Finish2(ref src, ref dst, position, v0, v1);
			offset += 32;
		}

		if (offset < source.Length)
		{
			nuint position = (nuint)offset;

			if (TDirection.IsDecrypt)
			{
				policy.Finish1(ref src, ref dst, position, core.Decrypt(policy.Prepare1(ref src, position)));
			}
			else
			{
				policy.Finish1(ref src, ref dst, position, core.Encrypt(policy.Prepare1(ref src, position)));
			}
		}
	}
}
