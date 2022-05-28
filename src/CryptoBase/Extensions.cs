using System.Numerics;

namespace CryptoBase;

public static class Extensions
{
	#region SodiumIncrement

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void IncrementInternal(this Span<byte> nonce)
	{
		for (int i = 0; i < nonce.Length; ++i)
		{
			if (++nonce[i] is not 0)
			{
				break;
			}
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Increment(this Span<byte> nonce)
	{
		nonce.IncrementInternal();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Increment(this byte[] nonce)
	{
		IncrementInternal(nonce);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void IncrementUInt(this byte[] nonce)
	{
		uint i = BinaryPrimitives.ReadUInt32LittleEndian(nonce);
		++i;
		BinaryPrimitives.WriteUInt32LittleEndian(nonce, i);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe void IncrementIntUnsafe(this byte[] nonce)
	{
		fixed (byte* p = nonce)
		{
			++*(uint*)p;
		}
	}

	/// <summary>
	/// https://github.com/jedisct1/libsodium/blob/master/src/libsodium/sodium/utils.c#L263
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void IncrementSource(this byte[] nonce)
	{
		uint i = 0;
		ushort c = 1;
		for (; i < nonce.Length; i++)
		{
			c += nonce[i];
			nonce[i] = (byte)c;
			c >>= 8;
		}
	}

	#endregion

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void IncrementBeInternal(this Span<byte> counter)
	{
		int j = counter.Length;
		while (--j >= 0 && ++counter[j] == 0)
		{
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void IncrementBe(this byte[] counter)
	{
		IncrementBeInternal(counter);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void IncrementBe(this Span<byte> counter)
	{
		counter.IncrementBeInternal();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static uint RotateLeft(this uint value, int offset)
	{
		return BitOperations.RotateLeft(value, offset);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int GetClassicHashCode(this string str)
	{
		unchecked
		{
			int hash1 = (5381 << 16) + 5381;
			int hash2 = hash1;

			for (int i = 0; i < str.Length; i += 2)
			{
				hash1 = ((hash1 << 5) + hash1) ^ str[i];
				if (i == str.Length - 1)
				{
					break;
				}

				hash2 = ((hash2 << 5) + hash2) ^ str[i + 1];
			}

			return hash1 + hash2 * 1566083941;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int GetDeterministicHashCode(this string str)
	{
		return str.AsSpan().GetDeterministicHashCode();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int GetDeterministicHashCode<T>(this ReadOnlySpan<T> span) where T : notnull
	{
		unchecked
		{
			int hash = 5381;

			foreach (T t in span)
			{
				hash = ((hash << 5) + hash) ^ t.GetHashCode();
			}

			return hash;
		}
	}
}