using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.Intrinsics.X86;
using System.Text;

namespace CryptoBase
{
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
				var id = X86Base.CpuId(0, 0);
				Span<byte> buffer = stackalloc byte[12];

				Debug.WriteLine(id);
				BinaryPrimitives.WriteInt32LittleEndian(buffer, id.Ebx);
				BinaryPrimitives.WriteInt32LittleEndian(buffer.Slice(4), id.Edx);
				BinaryPrimitives.WriteInt32LittleEndian(buffer.Slice(8), id.Ecx);

				return Encoding.ASCII.GetString(buffer);
			}

			return Unknown;
		}

		public static string GetBrand()
		{
			if (X86Base.IsSupported)
			{
				var id = X86Base.CpuId(unchecked((int)0x80000000), 0);
				var highestExtendedFunctionImplemented = (uint)id.Eax;

				if (highestExtendedFunctionImplemented >= 0x80000004)
				{
					Span<byte> buffer = stackalloc byte[48];

					var t = buffer;
					for (var i = 0x80000002; i <= 0x80000004; ++i)
					{
						var id2 = X86Base.CpuId(unchecked((int)i), 0);
						BinaryPrimitives.WriteInt32LittleEndian(t, id2.Eax);
						BinaryPrimitives.WriteInt32LittleEndian(t.Slice(4), id2.Ebx);
						BinaryPrimitives.WriteInt32LittleEndian(t.Slice(8), id2.Ecx);
						BinaryPrimitives.WriteInt32LittleEndian(t.Slice(12), id2.Edx);
						t = t.Slice(16);
					}

					return Encoding.ASCII.GetString(buffer);
				}
			}

			return Unknown;
		}

		public static bool IsSupportX86ShaEx()
		{
			if (X86Base.IsSupported)
			{
				var id = X86Base.CpuId(7, 0);
				Debug.WriteLine(id);

				return ((uint)id.Ebx >> 29 & 1) == 1;
			}

			return false;
		}
	}
}
