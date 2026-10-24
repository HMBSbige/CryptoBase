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
			(_, int ebx, int ecx, int edx) = X86Base.CpuId(0, 0);
			Span<byte> buffer = stackalloc byte[12];

			BinaryPrimitives.WriteInt32LittleEndian(buffer, ebx);
			BinaryPrimitives.WriteInt32LittleEndian(buffer.Slice(4), edx);
			BinaryPrimitives.WriteInt32LittleEndian(buffer.Slice(8), ecx);

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
		return X86Base.IsSupported && ((uint)X86Base.CpuId(7, 0).Ebx >> 29 & 1) is 1;
	}

	/// <summary>
	/// Gets a value indicating whether the processor supports vector AES instructions.
	/// </summary>
	public static bool IsSupportX86VAes()
	{
		return X86Base.IsSupported && ((uint)X86Base.CpuId(7, 0).Ecx >> 9 & 1) is 1;
	}

	private static readonly (int Family, int Model)? AmdFamilyAndModel = X86Base.IsSupported && IsAuthenticAmd(X86Base.CpuId(0, 0)) ? DecodeFamilyAndModel(X86Base.CpuId(1, 0).Eax) : null;

	internal static bool IsAmdZen5()
	{
		return AmdFamilyAndModel is var (family, model) && IsZen5(family, model);
	}

	internal static bool IsAmdZen5With512BitDatapath()
	{
		return AmdFamilyAndModel is var (family, model) && IsZen5With512BitDatapath(family, model);
	}

	internal static bool IsAmdWith256BitDatapath()
	{
		return AmdFamilyAndModel is var (family, model) && IsZenWith256BitDatapath(family, model);
	}

	internal static bool IsAuthenticAmd((int Eax, int Ebx, int Ecx, int Edx) id)
	{
		return id is (_, 0x68747541, 0x444D4163, 0x69746E65);
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

	// Strix Point and Krackan (20h-2Fh, 60h-6Fh) split 512-bit operations into two 256-bit halves; D0h-D7h is excluded because its datapath is unknown.
	internal static bool IsZen5With512BitDatapath(int family, int model)
	{
		return family is 0x1A && model is <= 0x1F or >= 0x40 and <= 0x4F or >= 0x70 and <= 0x7F;
	}

	// Zen 3 and Zen 4 (family 19h, where only Zen 4 has AVX-512), and the Zen 5 models that split 512-bit operations; D0h-D7h is again excluded because its datapath is unknown.
	internal static bool IsZenWith256BitDatapath(int family, int model)
	{
		return family is 0x19 || family is 0x1A && model is >= 0x20 and <= 0x2F or >= 0x60 and <= 0x6F;
	}
}
