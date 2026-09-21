namespace CryptoBase.Ciphers.Blocks.Aes;

/// <summary>Provides AES with automatic backend selection.</summary>
public sealed class AesCipher : IBlockCipher<AesCipher>
{
	/// <inheritdoc />
	public static int BlockSize => 16;

	private AesCipherX86 _x86;
	private AesCipherArm _arm;
	private AesCipherVpaes _vpaes;
	private AesCipherSoftware _software;
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

	private AesCipher(ReadOnlySpan<byte> key)
	{
		if (AesCipherX86.IsSupported)
		{
			_x86 = AesCipherX86.Create(key);
		}
		else if (AesCipherArm.IsSupported)
		{
			_arm = AesCipherArm.Create(key);
		}
		else if (AesCipherVpaes.IsSupported)
		{
			_vpaes = AesCipherVpaes.Create(key);
		}
		else
		{
			_software = AesCipherSoftware.Create(key);
		}
	}

	/// <inheritdoc />
	public static AesCipher Create(scoped ReadOnlySpan<byte> key)
	{
		return new AesCipher(key);
	}

	/// <inheritdoc />
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
		else if (AesCipherVpaes.IsSupported)
		{
			_vpaes.Dispose();
		}
		else
		{
			_software.Dispose();
		}
	}

	/// <inheritdoc />
	public void EncryptBlock(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, 16, nameof(source));
		EncryptBlocks(source, destination);
	}

	/// <inheritdoc />
	public void EncryptBlocks(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		CipherBufferGuard.Blocks(source, destination, 16);

		if (AesCipherX86.IsSupported)
		{
			_x86.EncryptBlocks(source, destination);
		}
		else if (AesCipherArm.IsSupported)
		{
			_arm.EncryptBlocks(source, destination);
		}
		else if (AesCipherVpaes.IsSupported)
		{
			_vpaes.EncryptBlocks(source, destination);
		}
		else
		{
			_software.EncryptBlocks(source, destination);
		}
	}

	/// <inheritdoc />
	public void DecryptBlock(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, 16, nameof(source));
		DecryptBlocks(source, destination);
	}

	/// <inheritdoc />
	public void DecryptBlocks(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		CipherBufferGuard.Blocks(source, destination, 16);

		if (AesCipherX86.IsSupported)
		{
			_x86.DecryptBlocks(source, destination);
		}
		else if (AesCipherArm.IsSupported)
		{
			_arm.DecryptBlocks(source, destination);
		}
		else if (AesCipherVpaes.IsSupported)
		{
			_vpaes.DecryptBlocks(source, destination);
		}
		else
		{
			_software.DecryptBlocks(source, destination);
		}
	}

	internal bool TryTransformWithMask(ReadOnlySpan<byte> source, ReadOnlySpan<byte> mask, Span<byte> destination, bool decrypt, bool xorInput)
	{
		if (AesCipherX86.IsSupported)
		{
			_x86.TransformWithMask(source, mask, destination, decrypt, xorInput);
			return true;
		}

		if (AesCipherArm.IsSupported)
		{
			_arm.TransformWithMask(source, mask, destination, decrypt, xorInput);
			return true;
		}

		if (AesCipherVpaes.IsSupported)
		{
			_vpaes.TransformWithMask(source, mask, destination, decrypt, xorInput);
			return true;
		}

		return false;
	}
}
