namespace CryptoBase.Digests;

public static class DigestUtils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IHash Create(DigestType type)
	{
		return type switch
		{
			DigestType.Sm3 => CreateSm3(),
			DigestType.Md5 => CreateMd5(),
			DigestType.Sha1 => CreateSha1(),
			DigestType.Sha224 => CreateSha224(),
			DigestType.Sha256 => CreateSha256(),
			DigestType.Sha384 => CreateSha384(),
			DigestType.Sha512 => CreateSha512(),
			DigestType.Crc32 => CreateCrc32(),
			DigestType.Crc32C => CreateCrc32C(),
			_ => throw new ArgumentOutOfRangeException(nameof(type), type, default)
		};
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static IHash CreateCrc32()
	{
		if (Crc32X86.IsSupport)
		{
			return new Crc32X86();
		}

		return new Crc32SF();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static IHash CreateCrc32C()
	{
		if (Crc32CX86.IsSupport)
		{
			return new Crc32CX86();
		}

		return new Crc32CSF();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static IHash CreateSm3()
	{
		return new SM3Digest();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static IHash CreateMd5()
	{
		return new DefaultMD5Digest();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static IHash CreateSha1()
	{
		return new DefaultSHA1Digest();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static IHash CreateSha224()
	{
		throw new NotImplementedException();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static IHash CreateSha256()
	{
		return new DefaultSHA256Digest();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static IHash CreateSha384()
	{
		return new DefaultSHA384Digest();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static IHash CreateSha512()
	{
		return new DefaultSHA512Digest();
	}

	public static async Task<byte[]> ComputeHashAsync(this IHash hasher, Stream inputStream, CancellationToken cancellationToken = default)
	{
		const int bufferSize = 81920;
		byte[] buffer = ArrayPool<byte>.Shared.Rent(bufferSize);

		try
		{
			while (true)
			{
				int length = await inputStream.ReadAsync(buffer, cancellationToken);

				if (length <= 0)
				{
					break;
				}

				hasher.Update(buffer.AsSpan(0, length));
			}

			byte[] result = new byte[hasher.Length];
			hasher.GetHash(result);
			return result;
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(buffer);
		}
	}
}
