namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

public sealed class AesCipher : IBlock16Cipher<AesCipher>
{
	private readonly AesCipherX86 _x86;
	private readonly AesCipherArm _arm;
	private readonly DefaultAesCipher _soft;

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

	private AesCipher(AesCipherX86 x86)
	{
		_x86 = x86;
		_arm = default!;
		_soft = default!;
	}

	private AesCipher(AesCipherArm arm)
	{
		_x86 = default!;
		_arm = arm;
		_soft = default!;
	}

	private AesCipher(DefaultAesCipher soft)
	{
		_x86 = default!;
		_arm = default!;
		_soft = soft;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Dispose()
	{
		if (AesCipherX86.IsSupported)
		{
			_x86.Dispose();
		}
		else if (AesCipherArm.IsSupported)
		{
			_arm.Dispose();
		}
		else
		{
			_soft.Dispose();
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static AesCipher Create(in ReadOnlySpan<byte> key)
	{
		if (AesCipherX86.IsSupported)
		{
			return new AesCipher(AesCipherX86.Create(key));
		}

		if (AesCipherArm.IsSupported)
		{
			return new AesCipher(AesCipherArm.Create(key));
		}

		return new AesCipher(DefaultAesCipher.Create(key));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer16 Encrypt(scoped in VectorBuffer16 source)
	{
		if (AesCipherX86.IsSupported)
		{
			return _x86.Encrypt(source);
		}

		if (AesCipherArm.IsSupported)
		{
			return _arm.Encrypt(source);
		}

		return _soft.Encrypt(source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer16 Decrypt(scoped in VectorBuffer16 source)
	{
		if (AesCipherX86.IsSupported)
		{
			return _x86.Decrypt(source);
		}

		if (AesCipherArm.IsSupported)
		{
			return _arm.Decrypt(source);
		}

		return _soft.Decrypt(source);
	}
}
