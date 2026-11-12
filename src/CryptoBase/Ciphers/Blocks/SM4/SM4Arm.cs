#if NET11_0_OR_GREATER
namespace CryptoBase.Ciphers.Blocks.SM4;

// SM4E runs four rounds of one block held in its own vector, so blocks need no transposition and a partial batch no padding.
internal readonly struct SM4Arm : ISM4Kernel
{
	public static bool IsSupported
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => Sm4.IsSupported && AdvSimd.Arm64.IsSupported;
	}

	// The Neoverse N2, V1 and V2 run SM4E down one pipeline at one a cycle with a latency of four, so four blocks keep it busy; eight, as in OpenSSL and Linux, halve the round key loads for each block.
	public static int MaxBlocks => 8;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Process(int width, int count, ref uint rk, ref byte source, ref byte destination)
	{
		Debug.Assert(IsSupported && width is 4 or 8 && count > 0 && count <= width);

		// The driver passes a single block as (4, 1) and a full batch as (8, 8); constant arguments fold these to straight-line code at the call site.
		if (width is 4 && count is 1)
		{
			Transform(1, ref rk, ref source, ref destination);
		}
		else if (width is 8 && count is 8)
		{
			Transform(8, ref rk, ref source, ref destination);
		}
		else
		{
			ProcessPartial(count, ref rk, ref source, ref destination);
		}
	}

	// Interleaves exactly count blocks instead of padding to the width, which would only add SM4E on a core where they limit throughput rather than latency.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void ProcessPartial(int count, ref uint rk, ref byte source, ref byte destination)
	{
		switch (count)
		{
			case 1:
				Transform(1, ref rk, ref source, ref destination);
				break;
			case 2:
				Transform(2, ref rk, ref source, ref destination);
				break;
			case 3:
				Transform(3, ref rk, ref source, ref destination);
				break;
			case 4:
				Transform(4, ref rk, ref source, ref destination);
				break;
			case 5:
				Transform(5, ref rk, ref source, ref destination);
				break;
			case 6:
				Transform(6, ref rk, ref source, ref destination);
				break;
			case 7:
				Transform(7, ref rk, ref source, ref destination);
				break;
			default:
				Transform(8, ref rk, ref source, ref destination);
				break;
		}
	}

	// blocks is a constant at every call, so the branches on it fold away and only its own blocks remain.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Transform(int blocks, ref uint rk, ref byte source, ref byte destination)
	{
		Vector128<uint> x0 = Load(ref source, 0);
		Vector128<uint> x1 = blocks > 1 ? Load(ref source, 1) : default;
		Vector128<uint> x2 = blocks > 2 ? Load(ref source, 2) : default;
		Vector128<uint> x3 = blocks > 3 ? Load(ref source, 3) : default;
		Vector128<uint> x4 = blocks > 4 ? Load(ref source, 4) : default;
		Vector128<uint> x5 = blocks > 5 ? Load(ref source, 5) : default;
		Vector128<uint> x6 = blocks > 6 ? Load(ref source, 6) : default;
		Vector128<uint> x7 = blocks > 7 ? Load(ref source, 7) : default;

		// Each round key vector goes to every block before the next, so the blocks' SM4E chains overlap instead of waiting on one another.
		for (nuint i = 0; i < 8; ++i)
		{
			Vector128<uint> key = Vector128.LoadUnsafe(ref rk, i * 4);
			x0 = Sm4.Encode(x0, key);

			if (blocks > 1)
			{
				x1 = Sm4.Encode(x1, key);
			}

			if (blocks > 2)
			{
				x2 = Sm4.Encode(x2, key);
			}

			if (blocks > 3)
			{
				x3 = Sm4.Encode(x3, key);
			}

			if (blocks > 4)
			{
				x4 = Sm4.Encode(x4, key);
			}

			if (blocks > 5)
			{
				x5 = Sm4.Encode(x5, key);
			}

			if (blocks > 6)
			{
				x6 = Sm4.Encode(x6, key);
			}

			if (blocks > 7)
			{
				x7 = Sm4.Encode(x7, key);
			}
		}

		Store(ref destination, 0, x0);

		if (blocks > 1)
		{
			Store(ref destination, 1, x1);
		}

		if (blocks > 2)
		{
			Store(ref destination, 2, x2);
		}

		if (blocks > 3)
		{
			Store(ref destination, 3, x3);
		}

		if (blocks > 4)
		{
			Store(ref destination, 4, x4);
		}

		if (blocks > 5)
		{
			Store(ref destination, 5, x5);
		}

		if (blocks > 6)
		{
			Store(ref destination, 6, x6);
		}

		if (blocks > 7)
		{
			Store(ref destination, 7, x7);
		}
	}

	// SM4E takes the four words of the state in element order, X0 first.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> Load(ref byte source, nuint block)
	{
		return Vector128.LoadUnsafe(ref source, block * 16).AsUInt32().ReverseEndianness32();
	}

	// SM4E leaves (X32, X33, X34, X35), and the block is X35 to X32 in big-endian order: the bytes of the vector reversed.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Store(ref byte destination, nuint block, Vector128<uint> x)
	{
		x.ReverseEndianness128().AsByte().StoreUnsafe(ref destination, block * 16);
	}
}
#endif
