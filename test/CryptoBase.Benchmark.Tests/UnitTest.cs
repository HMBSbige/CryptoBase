using System.Runtime.Intrinsics.X86;

namespace CryptoBase.Benchmark.Tests;

[TestClass]
public class UnitTest
{
	[TestMethod]
	public void EnvironmentTest()
	{
		Console.WriteLine($@"OS Version:                                     {Environment.OSVersion}");
		Console.WriteLine($@".NET Version:                                   {Environment.Version}");
		Console.WriteLine($@"App Version:                                    {Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion}");
		Console.WriteLine($@"CPU Vendor:                                     {CpuIdUtils.GetVendor()}");
		Console.WriteLine($@"CPU Brand:                                      {CpuIdUtils.GetBrand()}");

		Console.WriteLine($@"Vector64.IsHardwareAccelerated:                 {Vector64.IsHardwareAccelerated}");
		Console.WriteLine($@"Vector128.IsHardwareAccelerated:                {Vector128.IsHardwareAccelerated}");
		Console.WriteLine($@"Vector256.IsHardwareAccelerated:                {Vector256.IsHardwareAccelerated}");
		Console.WriteLine($@"Vector512.IsHardwareAccelerated:                {Vector512.IsHardwareAccelerated}");

		Console.WriteLine($@"SSE2 instructions:                              {Sse2.IsSupported}");
		Console.WriteLine($@"Advanced Vector Extensions 2:                   {Avx2.IsSupported}");
		Console.WriteLine($@"Intel SHA extensions:                           {CpuIdUtils.IsSupportX86ShaEx()}");
		Console.WriteLine($@"AES instruction set:                            {Aes.IsSupported}");
		Console.WriteLine($@"Vector AES instruction:                         {CpuIdUtils.IsSupportX86VAes()}");

		Console.WriteLine($@"AVX-512 Foundation:                             {Avx512F.IsSupported}");
		Console.WriteLine($@"AVX-512 Conflict Detection Instructions:        {Avx512CD.IsSupported}");
		Console.WriteLine($@"AVX-512 Byte and Word Instructions:             {Avx512BW.IsSupported}");
		Console.WriteLine($@"AVX-512 Doubleword and Quadword Instructions:   {Avx512DQ.IsSupported}");
		Console.WriteLine($@"AVX-512 Vector Byte Manipulation Instructions:  {Avx512Vbmi.IsSupported}");
	}
}
