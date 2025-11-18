using System.Numerics;
using System.Reflection;

namespace CryptoBase;

public static class SystemEnvironmentUtils
{
	public static string GetEnvironmentInfo()
	{
		DefaultInterpolatedStringHandler handler = new();
		handler.AppendLiteral
		(
			$"""
			OS Version:                                     {Environment.OSVersion}
			.NET Version:                                   {Environment.Version}
			App Version:                                    {Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion}
			Vector<byte>.Count:                             {Vector<byte>.Count}
			Vector.IsHardwareAccelerated:                   {Vector.IsHardwareAccelerated}
			Vector64.IsHardwareAccelerated:                 {Vector64.IsHardwareAccelerated}
			Vector128.IsHardwareAccelerated:                {Vector128.IsHardwareAccelerated}
			Vector256.IsHardwareAccelerated:                {Vector256.IsHardwareAccelerated}
			Vector512.IsHardwareAccelerated:                {Vector512.IsHardwareAccelerated}
			"""
		);
		handler.AppendLiteral(Environment.NewLine);

		if (X86Base.IsSupported)
		{
			handler.AppendLiteral
			(
				$"""
				CPU Vendor:                                     {CpuIdUtils.GetVendor()}
				CPU Brand:                                      {CpuIdUtils.GetBrand()}
				SSE2 instructions:                              {Sse2.IsSupported}
				Advanced Vector Extensions 2:                   {Avx2.IsSupported}
				Intel SHA extensions:                           {CpuIdUtils.IsSupportX86ShaEx()}
				AES instruction set:                            {AesX86.IsSupported}
				Vector AES instruction:                         {CpuIdUtils.IsSupportX86VAes()}
				AVX-512 Foundation:                             {Avx512F.IsSupported}
				AVX-512 Conflict Detection Instructions:        {Avx512CD.IsSupported}
				AVX-512 Byte and Word Instructions:             {Avx512BW.IsSupported}
				AVX-512 Doubleword and Quadword Instructions:   {Avx512DQ.IsSupported}
				AVX-512 Vector Bit Manipulation Instructions:   {Avx512Vbmi.IsSupported}
				AVX-512 Vector Bit Manipulation Instructions 2: {Avx512Vbmi2.IsSupported}
				GFNI:                                           {Gfni.IsSupported}
				GFNI/256:                                       {Gfni.V256.IsSupported}
				GFNI/512:                                       {Gfni.V512.IsSupported}
				AVX10.1:                                        {Avx10v1.IsSupported}
				AVX10.1/512:                                    {Avx10v1.V512.IsSupported}
				AVX10.2:                                        {Avx10v2.IsSupported}
				AVX10.2/512:                                    {Avx10v2.V512.IsSupported}
				"""
			);
			handler.AppendLiteral(Environment.NewLine);
		}

		if (ArmBase.IsSupported)
		{
			handler.AppendLiteral(
				$"""
				AES hardware instructions:                      {AesArm.IsSupported}
				Crc32 hardware instructions:                    {Crc32.IsSupported}
				ARMv8.1-RDMA hardware instructions:             {Rdm.IsSupported}
				ARMv8.2-DotProd hardware instructions:          {Dp.IsSupported}
				SHA1 hardware instructions:                     {Sha1.IsSupported}
				SHA256 hardware instructions:                   {Sha256.IsSupported}
				"""
			);
			handler.AppendLiteral(Environment.NewLine);
		}

		return handler.ToStringAndClear();
	}
}
