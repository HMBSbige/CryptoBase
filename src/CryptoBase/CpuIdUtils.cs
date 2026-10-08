using System.Text;

namespace CryptoBase;

/// <summary>
/// https://en.wikipedia.org/wiki/CPUID
/// </summary>
public static class CpuIdUtils
{
	private const string Unknown = @"Unknown";

	/// <summary>
	/// Gets the CPU vendor identification string.
	/// </summary>
	public static string GetVendor()
	{
		if (X86Base.IsSupported)
		{
			(int Eax, int Ebx, int Ecx, int Edx) id = X86Base.CpuId(0, 0);
			Span<byte> buffer = stackalloc byte[12];

			Debug.WriteLine(id);
			BinaryPrimitives.WriteInt32LittleEndian(buffer, id.Ebx);
			BinaryPrimitives.WriteInt32LittleEndian(buffer.Slice(4), id.Edx);
			BinaryPrimitives.WriteInt32LittleEndian(buffer.Slice(8), id.Ecx);

			return Encoding.ASCII.GetString(buffer.TrimEnd(byte.MinValue));
		}

		return Unknown;
	}

	/// <summary>
	/// Gets the CPU brand string.
	/// </summary>
	public static string GetBrand()
	{
		if (X86Base.IsSupported)
		{
			(int eax, int _, int _, int _) = X86Base.CpuId(int.MinValue, 0);
			uint highestExtendedFunctionImplemented = (uint)eax;

			if (highestExtendedFunctionImplemented >= 0x80000004)
			{
				Span<byte> buffer = stackalloc byte[48];

				Span<byte> t = buffer;

				for (uint i = 0x80000002; i <= 0x80000004; ++i)
				{
					(eax, int ebx, int ecx, int edx) = X86Base.CpuId((int)i, 0);
					BinaryPrimitives.WriteInt32LittleEndian(t, eax);
					BinaryPrimitives.WriteInt32LittleEndian(t.Slice(4), ebx);
					BinaryPrimitives.WriteInt32LittleEndian(t.Slice(8), ecx);
					BinaryPrimitives.WriteInt32LittleEndian(t.Slice(12), edx);
					t = t.Slice(16);
				}

				return Encoding.ASCII.GetString(buffer.TrimEnd("\0 "u8));
			}
		}

		return Unknown;
	}

	/// <summary>
	/// Gets a value indicating whether the processor supports Intel SHA extensions.
	/// </summary>
	public static bool IsSupportX86ShaEx()
	{
		if (X86Base.IsSupported)
		{
			(int Eax, int Ebx, int Ecx, int Edx) id = X86Base.CpuId(7, 0);
			Debug.WriteLine(id);

			return ((uint)id.Ebx >> 29 & 1) is 1;
		}

		return false;
	}

	/// <summary>
	/// Gets a value indicating whether the processor supports vector AES instructions.
	/// </summary>
	public static bool IsSupportX86VAes()
	{
		if (X86Base.IsSupported)
		{
			(int Eax, int Ebx, int Ecx, int Edx) id = X86Base.CpuId(7, 0);
			Debug.WriteLine(id);

			return ((uint)id.Ecx >> 9 & 1) is 1;
		}

		return false;
	}

	internal static bool IsAmdZen5()
	{
		if (!X86Base.IsSupported)
		{
			return false;
		}

		(int family, int model) = DecodeFamilyAndModel(X86Base.CpuId(1, 0).Eax);
		return IsZen5(family, model) && GetVendor() is "AuthenticAMD";
	}

	internal static (int Family, int Model) DecodeFamilyAndModel(int signature)
	{
		int family = signature >> 8 & 0xF;
		int model = signature >> 4 & 0xF;

		if (family is 6 or 0xF)
		{
			model |= signature >> 12 & 0xF0;
		}

		if (family is 0xF)
		{
			family += signature >> 20 & 0xFF;
		}

		return (family, model);
	}

	internal static bool IsZen5(int family, int model)
	{
		return family is 0x1A && model is <= 0x2F or >= 0x40 and <= 0x4F or >= 0x60 and <= 0x7F or >= 0xD0 and <= 0xD7;
	}
}
