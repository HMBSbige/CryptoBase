global using CryptoBase;
global using CryptoBase.Abstractions.SymmetricCryptos;
global using CryptoBase.SpeedTest;
global using CryptoBase.SymmetricCryptos.AEADCryptos;
global using CryptoBase.SymmetricCryptos.StreamCryptos;
global using System.Collections.Immutable;
global using System.CommandLine;
global using System.Diagnostics;
global using System.Reflection;
global using System.Runtime.Intrinsics.X86;
global using System.Security.Cryptography;
global using Aes = System.Runtime.Intrinsics.X86.Aes;

#if DEBUG
Console.WriteLine(@"On Debug mode");
#endif
if (Debugger.IsAttached)
{
	Console.WriteLine(@"Debugger attached!");
}

Argument<string> methodsArgument = new(@"method(s)", () => CryptoList.All, @"Methods separated by commas.");
methodsArgument.AddCompletions(CryptoList.All);
foreach (string method in CryptoList.Methods)
{
	methodsArgument.AddCompletions(method);
}
Option<double> secondsOption = new(@"--seconds", () => 3.0, @"Run benchmarks for num seconds.");
secondsOption.AddAlias(@"-s");
Option<int> bytesOption = new(@"--bytes", () => 8 * 1024, @"Run benchmarks on num-byte buffers.");
bytesOption.AddAlias(@"-b");

RootCommand cmd = new()
{
	methodsArgument,
	secondsOption,
	bytesOption
};

cmd.SetHandler((string methods, double seconds, int bytes) =>
{
	Console.WriteLine($@"OS Version:                    {Environment.OSVersion}");
	Console.WriteLine($@".NET Version:                  {Environment.Version}");
	Console.WriteLine($@"App Version:                   {Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion}");
	Console.WriteLine($@"CPU Vendor:                    {CpuIdUtils.GetVendor()}");
	Console.WriteLine($@"CPU Brand:                     {CpuIdUtils.GetBrand()}");
	Console.WriteLine($@"SSE2 instructions:             {Sse2.IsSupported}");
	Console.WriteLine($@"Advanced Vector Extensions 2:  {Avx2.IsSupported}");
	Console.WriteLine($@"Intel SHA extensions:          {CpuIdUtils.IsSupportX86ShaEx()}");
	Console.WriteLine($@"AES instruction set:           {Aes.IsSupported}");
	Console.WriteLine($@"Vector AES instruction set:    {CpuIdUtils.IsSupportX86VAes()}");
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
		ISymmetricCrypto? crypto = CryptoList.GetSymmetricCrypto(realMethod);
		if (crypto is null)
		{
			throw new NotSupportedException($@"{realMethod} is not supported.");
		}

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
}, methodsArgument, secondsOption, bytesOption);

return cmd.Invoke(args);
