using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace CryptoBase
{
	public static class FastUtils
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static ref T GetRef<T>(this T[] array, int index)
		{
			ref var data = ref MemoryMarshal.GetArrayDataReference(array);
			return ref Unsafe.Add(ref data, index);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static unsafe void Copy(byte* source, byte* destination, int count)
		{
			while (count >= 8)
			{
				*(ulong*)destination = *(ulong*)source;
				destination += 8;
				source += 8;
				count -= 8;
			}

			if (count >= 4)
			{
				*(uint*)destination = *(uint*)source;
				destination += 4;
				source += 4;
				count -= 4;
			}

			if (count >= 2)
			{
				*(ushort*)destination = *(ushort*)source;
				destination += 2;
				source += 2;
				count -= 2;
			}

			if (count >= 1)
			{
				*destination = *source;
			}
		}
	}
}
