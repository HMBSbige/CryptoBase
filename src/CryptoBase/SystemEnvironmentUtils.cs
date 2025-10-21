using System.Numerics;
using System.Reflection;

namespace CryptoBase;

public static class SystemEnvironmentUtils
{
	public static string GetEnvironmentInfo()
	{
		return $"""
				OS Version:                                     {Environment.OSVersion}
				.NET Version:                                   {Environment.Version}
				App Version:                                    {Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion}
				CPU Vendor:                                     {CpuIdUtils.GetVendor()}
				CPU Brand:                                      {CpuIdUtils.GetBrand()}
				Vector<byte>.Count:                             {Vector<byte>.Count}
				Vector.IsHardwareAccelerated:                   {Vector.IsHardwareAccelerated}
				Vector64.IsHardwareAccelerated:                 {Vector64.IsHardwareAccelerated}
				Vector128.IsHardwareAccelerated:                {Vector128.IsHardwareAccelerated}
				Vector256.IsHardwareAccelerated:                {Vector256.IsHardwareAccelerated}
				Vector512.IsHardwareAccelerated:                {Vector512.IsHardwareAccelerated}
				SSE2 instructions:                              {Sse2.IsSupported}
				Advanced Vector Extensions 2:                   {Avx2.IsSupported}
				Intel SHA extensions:                           {CpuIdUtils.IsSupportX86ShaEx()}
				AES instruction set:                            {Aes.IsSupported}
				Vector AES instruction:                         {CpuIdUtils.IsSupportX86VAes()}
				AVX-512 Foundation:                             {Avx512F.IsSupported}
				AVX-512 Conflict Detection Instructions:        {Avx512CD.IsSupported}
				AVX-512 Byte and Word Instructions:             {Avx512BW.IsSupported}
				AVX-512 Doubleword and Quadword Instructions:   {Avx512DQ.IsSupported}
				AVX-512 Vector Byte Manipulation Instructions:  {Avx512Vbmi.IsSupported}
				AVX10.1:                                        {Avx10v1.IsSupported}
				AVX10.1/512:                                    {Avx10v1.V512.IsSupported}
				""";

		// TODO: Gfni
		// TODO: AVX-512 Vector Bit Manipulation Instructions 2:  {Avx512Vbmi2.IsSupported};
		// TODO: AVX10.2:  {Avx10v2.IsSupported};
		// TODO: AVX10.2/512:  {Avx10v2.V512.IsSupported};
	}
}
