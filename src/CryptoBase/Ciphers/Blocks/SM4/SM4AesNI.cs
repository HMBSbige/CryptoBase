using AesX86 = System.Runtime.Intrinsics.X86.Aes;

namespace CryptoBase.Ciphers.Blocks.SM4;

internal readonly partial struct SM4AesNI : ISM4Kernel
{
	// Vector-valued properties prevented the JIT from hoisting these constants out of the round loop.
	private const ulong PreAffineLow0 = 0x9197E2E474720701;
	private const ulong PreAffineLow1 = 0xC7C1B4B222245157;
	private const ulong PreAffineHigh0 = 0xE240AB09EB49A200;
	private const ulong PreAffineHigh1 = 0xF052B91BF95BB012;
	private const ulong PostAffineLow0 = 0x5B67F2CEA19D0834;
	private const ulong PostAffineLow1 = 0xEDD14478172BBE82;
	private const ulong PostAffineHigh0 = 0xAE7201DD73AFDC00;
	private const ulong PostAffineHigh1 = 0x11CDBE62CC1063BF;

	public static bool IsSupported => AesX86.IsSupported && Ssse3.IsSupported;

	public static int MaxBlocks => Avx2.IsSupported ? 16 : 8;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Process(int width, int count, ref uint rk, ref byte source, ref byte destination)
	{
		Debug.Assert(IsSupported && (width is 4 or 8 || width is 16 && MaxBlocks is 16));
		Debug.Assert(count > 0 && count <= width);

		if (width is 4)
		{
			Process4V128(count, ref rk, ref source, ref destination);
		}
		else if (!Avx2.IsSupported)
		{
			Process8V128(count, ref rk, ref source, ref destination);
		}
		else if (width is 8)
		{
			Process8V256(count, ref rk, ref source, ref destination);
		}
		else
		{
			Process16V256(count, ref rk, ref source, ref destination);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static uint SubByte(uint value)
	{
		return Substitute(Vector128.Create(value).AsByte()).AsUInt32().ToScalar();
	}
}
