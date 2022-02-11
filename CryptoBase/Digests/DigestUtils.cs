using CryptoBase.Abstractions.Digests;
using CryptoBase.Digests.CRC32;
using CryptoBase.Digests.CRC32C;
using CryptoBase.Digests.MD5;
using CryptoBase.Digests.SHA1;
using CryptoBase.Digests.SHA256;
using CryptoBase.Digests.SHA384;
using CryptoBase.Digests.SHA512;
using CryptoBase.Digests.SM3;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace CryptoBase.Digests;

public static class DigestUtils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IHash Create(DigestType type)
	{
		return type switch
		{
			DigestType.Sm3 => new SM3Digest(),
			DigestType.Md5 => new DefaultMD5Digest(),
			DigestType.Sha1 => new DefaultSHA1Digest(),
			DigestType.Sha256 => new DefaultSHA256Digest(),
			DigestType.Sha384 => new DefaultSHA384Digest(),
			DigestType.Sha512 => new DefaultSHA512Digest(),
			DigestType.Crc32 => CreateCrc32(),
			DigestType.Crc32C => CreateCrc32C(),
			_ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
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
