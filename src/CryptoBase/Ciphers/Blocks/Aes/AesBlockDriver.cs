namespace CryptoBase.Ciphers.Blocks.Aes;

internal static class AesBlockDriver<TCore> where TCore : struct, IAesVectorCore
{
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void EncryptBlocks(ref TCore core, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		AesDirectPolicy policy = default;
		Process<AesDirectPolicy, AesEncrypt>(ref core, ref policy, source, destination);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void DecryptBlocks(ref TCore core, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		AesDirectPolicy policy = default;
		Process<AesDirectPolicy, AesDecrypt>(ref core, ref policy, source, destination);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void TransformWithPolicy<TPolicy, TOperation>(ref TCore core, ref TPolicy policy, ReadOnlySpan<byte> source, Span<byte> destination) where TPolicy : struct, IAesModePolicy, allows ref struct where TOperation : struct, IAesOperation
	{
		Process<TPolicy, TOperation>(ref core, ref policy, source, destination);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void Transform<TPolicy, TOperation>(ref TCore core, ref Vector128<byte> state, ReadOnlySpan<byte> source, Span<byte> destination) where TPolicy : struct, IAesModePolicy where TOperation : struct, IAesOperation
	{
		Debug.Assert(source.Length % 16 is 0 && destination.Length >= source.Length);
		TPolicy policy = default;
		policy.Initialize(state, source.Length);
		Process<TPolicy, TOperation>(ref core, ref policy, source, destination);
		policy.SaveState(ref state);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Process<TPolicy, TOperation>(ref TCore core, ref TPolicy policy, ReadOnlySpan<byte> source, Span<byte> destination) where TPolicy : struct, IAesModePolicy, allows ref struct where TOperation : struct, IAesOperation
	{
		ref byte src = ref source.GetReference();
		ref byte dst = ref destination.GetReference();
		int offset = 0;

		if (TPolicy.UseBatch8)
		{
			while (offset <= source.Length - 128)
			{
				nuint position = (nuint)offset;
				policy.Prepare8(ref src, position, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3, out Vector128<byte> v4, out Vector128<byte> v5, out Vector128<byte> v6, out Vector128<byte> v7);

				TOperation.Apply8(ref core, ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);

				policy.Finish8(ref src, ref dst, position, v0, v1, v2, v3, v4, v5, v6, v7);
				offset += 128;
			}
		}

		while (offset <= source.Length - 64)
		{
			nuint position = (nuint)offset;
			policy.Prepare4(ref src, position, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3);

			TOperation.Apply4(ref core, ref v0, ref v1, ref v2, ref v3);

			policy.Finish4(ref src, ref dst, position, v0, v1, v2, v3);
			offset += 64;
		}

		if (offset <= source.Length - 32)
		{
			nuint position = (nuint)offset;
			policy.Prepare2(ref src, position, out Vector128<byte> v0, out Vector128<byte> v1);

			TOperation.Apply2(ref core, ref v0, ref v1);

			policy.Finish2(ref src, ref dst, position, v0, v1);
			offset += 32;
		}

		if (offset < source.Length)
		{
			nuint position = (nuint)offset;
			Vector128<byte> value = policy.Prepare1(ref src, position);
			value = TOperation.Apply1(ref core, value);
			policy.Finish1(ref src, ref dst, position, value);
		}
	}
}
