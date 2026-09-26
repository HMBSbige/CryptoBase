using System.Numerics;

namespace CryptoBase.Ciphers.Blocks.SM4;

internal readonly partial struct SM4Gfni : ISM4Kernel
{
	// S(x) = PostAffine · Inverse(PreAffine · x + PreConstant) + PostConstant.
	private const ulong PreAffine = 0x669B0D608A162E14;
	private const byte PreConstant = 0x01;
	private const ulong PostAffine = 0x598EDB70229CA40E;
	private const byte PostConstant = 0xD3;

	public static bool IsSupported => Gfni.IsSupported && Ssse3.IsSupported;

	public static int MaxBlocks
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get
		{
			if (!Gfni.V256.IsSupported || !Avx2.IsSupported)
			{
				return 8;
			}

			return Vector512.IsHardwareAccelerated && Gfni.V512.IsSupported ? 64 : 16;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Process(int width, int count, ref uint rk, ref byte source, ref byte destination)
	{
		Debug.Assert(IsSupported && width >= 4 && width <= MaxBlocks && BitOperations.IsPow2(width));
		Debug.Assert(count > 0 && count <= width);

		if (width is 4)
		{
			Process4V128(count, ref rk, ref source, ref destination);
		}
		else if (width is 8)
		{
			if (Gfni.V256.IsSupported && Avx2.IsSupported)
			{
				Process8V256(count, ref rk, ref source, ref destination);
			}
			else
			{
				Process8V128(count, ref rk, ref source, ref destination);
			}
		}
		else if (width is 16)
		{
			if (Vector512.IsHardwareAccelerated && Gfni.V512.IsSupported)
			{
				Process16V512(count, ref rk, ref source, ref destination);
			}
			else
			{
				Process16V256(count, ref rk, ref source, ref destination);
			}
		}
		else if (width is 32)
		{
			Process32V512(count, ref rk, ref source, ref destination);
		}
		else
		{
			Process64V512(count, ref rk, ref source, ref destination);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static uint SubByte(uint value)
	{
		return Substitute(Vector128.CreateScalar(value).AsByte()).AsUInt32().ToScalar();
	}
}
