global using CryptoBase;
global using CryptoBase.Abstractions.SymmetricCryptos;
global using CryptoBase.SpeedTest;
global using CryptoBase.SymmetricCryptos.AEADCryptos;
global using CryptoBase.SymmetricCryptos.StreamCryptos;
global using System.Collections.Immutable;
global using System.CommandLine;
global using System.Diagnostics;
global using System.Reflection;
global using System.Runtime.Intrinsics;
global using System.Security.Cryptography;
global using X86Aes = System.Runtime.Intrinsics.X86.Aes;
using System.Runtime.Intrinsics.X86;

#if DEBUG
Console.WriteLine(@"On Debug mode");
#endif
if (Debugger.IsAttached)
{
	Console.WriteLine(@"Debugger attached!");
}

Argument<string> methodsArgument = new(@"method(s)")
{
	Description = @"Methods separated by commas.",
	DefaultValueFactory = _ => CryptoList.All
};
methodsArgument.CompletionSources.Add(new[] { CryptoList.All });
methodsArgument.CompletionSources.Add(CryptoList.Methods.ToArray());

Option<double> secondsOption = new(@"--seconds", [@"-s"])
{
	Description = @"Run benchmarks for num seconds.",
	DefaultValueFactory = _ => 3.0
};

Option<int> bytesOption = new(@"--bytes", [@"-b"])
{
	Description = @"Run benchmarks on num-byte buffers.",
	DefaultValueFactory = _ => 8 * 1024
};

RootCommand cmd = new(@"CryptoBase Speed Test");
cmd.Add(methodsArgument);
cmd.Add(secondsOption);
cmd.Add(bytesOption);

cmd.SetAction((parseResult) =>
{
	string methods = parseResult.GetValue(methodsArgument)!;
	double seconds = parseResult.GetValue(secondsOption);
	int bytes = parseResult.GetValue(bytesOption);

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
	Console.WriteLine($@"AES instruction set:                            {X86Aes.IsSupported}");
	Console.WriteLine($@"Vector AES instruction:                         {CpuIdUtils.IsSupportX86VAes()}");

	Console.WriteLine($@"AVX-512 Foundation:                             {Avx512F.IsSupported}");
	Console.WriteLine($@"AVX-512 Conflict Detection Instructions:        {Avx512CD.IsSupported}");
	Console.WriteLine($@"AVX-512 Byte and Word Instructions:             {Avx512BW.IsSupported}");
	Console.WriteLine($@"AVX-512 Doubleword and Quadword Instructions:   {Avx512DQ.IsSupported}");
	Console.WriteLine($@"AVX-512 Vector Byte Manipulation Instructions:  {Avx512Vbmi.IsSupported}");

	Console.WriteLine($@"Seconds: {seconds}s");
	Console.WriteLine($@"Buffer size: {bytes} bytes");
	Console.WriteLine();

	IEnumerable<string> methodList = methods.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
	if (methodList.Contains(CryptoList.All, StringComparer.OrdinalIgnoreCase))
	{
		methodList = CryptoList.Methods;
	}

	foreach (string method in methodList)
	{
		string realMethod = method.ToLower();
		ISymmetricCrypto crypto = CryptoList.GetSymmetricCrypto(realMethod) ?? throw new NotSupportedException($@"{realMethod} is not supported.");

		Console.Write($@"Testing {realMethod}: ");

		CryptoTest t = new(bytes, seconds);
		switch (crypto)
		{
			case XChaCha20Poly1305Crypto xc20P1305:
			{
				t.Test(xc20P1305, 24);
				break;
			}
			case IStreamCrypto streamCrypto:
			{
				t.Test(streamCrypto);
				break;
			}
			case IAEADCrypto aeadCrypto:
			{
				t.Test(aeadCrypto);
				break;
			}
		}
	}
});

return cmd.Parse(args).Invoke();
