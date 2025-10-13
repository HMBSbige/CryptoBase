using System.Diagnostics;
using System.Text;

namespace CryptoBase;

/// <summary>
/// https://en.wikipedia.org/wiki/CPUID
/// </summary>
public static class CpuIdUtils
{
	private const string Unknown = @"Unknown";

	public static string GetVendor()
	{
		if (X86Base.IsSupported)
		{
			(int Eax, int Ebx, int Ecx, int Edx) id = X86Base.CpuId(0, 0);
			Span<byte> buffer = stackalloc byte[12];

			Debug.WriteLine(id);
			BinaryPrimitives.WriteInt32LittleEndian(buffer, id.Ebx);
			BinaryPrimitives.WriteInt32LittleEndian(buffer[4..], id.Edx);
			BinaryPrimitives.WriteInt32LittleEndian(buffer[8..], id.Ecx);

			return Encoding.ASCII.GetString(buffer.TrimEnd(byte.MinValue));
		}

		return Unknown;
	}

	public static string GetBrand()
	{
		if (X86Base.IsSupported)
		{
			(int Eax, int Ebx, int Ecx, int Edx) id = X86Base.CpuId(unchecked((int)0x80000000), 0);
			uint highestExtendedFunctionImplemented = (uint)id.Eax;

			if (highestExtendedFunctionImplemented >= 0x80000004)
			{
				Span<byte> buffer = stackalloc byte[48];

				Span<byte> t = buffer;
				for (uint i = 0x80000002; i <= 0x80000004; ++i)
				{
					(int Eax, int Ebx, int Ecx, int Edx) id2 = X86Base.CpuId(unchecked((int)i), 0);
					BinaryPrimitives.WriteInt32LittleEndian(t, id2.Eax);
					BinaryPrimitives.WriteInt32LittleEndian(t[4..], id2.Ebx);
					BinaryPrimitives.WriteInt32LittleEndian(t[8..], id2.Ecx);
					BinaryPrimitives.WriteInt32LittleEndian(t[12..], id2.Edx);
					t = t[16..];
				}

				return Encoding.ASCII.GetString(buffer.TrimEnd("\0 "u8));
			}
		}

		return Unknown;
	}

	public static bool IsSupportX86ShaEx()
	{
		if (X86Base.IsSupported)
		{
			(int Eax, int Ebx, int Ecx, int Edx) id = X86Base.CpuId(7, 0);
			Debug.WriteLine(id);

			return ((uint)id.Ebx >> 29 & 1) == 1;
		}

		return false;
	}

	public static bool IsSupportX86VAes()
	{
		if (X86Base.IsSupported)
		{
			(int Eax, int Ebx, int Ecx, int Edx) id = X86Base.CpuId(7, 0);
			Debug.WriteLine(id);

			return ((uint)id.Ecx >> 9 & 1) == 1;
		}

		return false;
	}
}
