namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

public sealed class AesCryptoNg : IBlock16Crypto<AesCryptoNg>
{
	private readonly AesCryptoX86Ng _x86;
	private readonly AesCryptoArmNg _arm;
	private readonly DefaultAesCryptoNg _soft;

	public static bool IsSupported => true;

	internal const byte Rcon0 = 0x00;
	internal const byte Rcon1 = 0x01;
	internal const byte Rcon2 = 0x02;
	internal const byte Rcon3 = 0x04;
	internal const byte Rcon4 = 0x08;
	internal const byte Rcon5 = 0x10;
	internal const byte Rcon6 = 0x20;
	internal const byte Rcon7 = 0x40;
	internal const byte Rcon8 = 0x80;
	internal const byte Rcon9 = 0x1b;
	internal const byte Rcon10 = 0x36;

	internal static ReadOnlySpan<byte> Rcon => [Rcon0, Rcon1, Rcon2, Rcon3, Rcon4, Rcon5, Rcon6, Rcon7, Rcon8, Rcon9, Rcon10];

	private AesCryptoNg(AesCryptoX86Ng x86)
	{
		_x86 = x86;
		_arm = default!;
		_soft = default!;
	}

	private AesCryptoNg(AesCryptoArmNg arm)
	{
		_x86 = default!;
		_arm = arm;
		_soft = default!;
	}

	private AesCryptoNg(DefaultAesCryptoNg soft)
	{
		_x86 = default!;
		_arm = default!;
		_soft = soft;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Dispose()
	{
		if (AesCryptoX86Ng.IsSupported)
		{
			_x86.Dispose();
		}
		else if (AesCryptoArmNg.IsSupported)
		{
			_arm.Dispose();
		}
		else
		{
			_soft.Dispose();
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static AesCryptoNg Create(in ReadOnlySpan<byte> key)
	{
		if (AesCryptoX86Ng.IsSupported)
		{
			return new AesCryptoNg(AesCryptoX86Ng.Create(key));
		}

		if (AesCryptoArmNg.IsSupported)
		{
			return new AesCryptoNg(AesCryptoArmNg.Create(key));
		}

		return new AesCryptoNg(DefaultAesCryptoNg.Create(key));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer16 Encrypt(scoped in VectorBuffer16 source)
	{
		if (AesCryptoX86Ng.IsSupported)
		{
			return _x86.Encrypt(source);
		}

		if (AesCryptoArmNg.IsSupported)
		{
			return _arm.Encrypt(source);
		}

		return _soft.Encrypt(source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer16 Decrypt(scoped in VectorBuffer16 source)
	{
		if (AesCryptoX86Ng.IsSupported)
		{
			return _x86.Decrypt(source);
		}

		if (AesCryptoArmNg.IsSupported)
		{
			return _arm.Decrypt(source);
		}

		return _soft.Decrypt(source);
	}
}
