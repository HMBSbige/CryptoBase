global using CryptoBase;
global using CryptoBase.Abstractions.SymmetricCryptos;
global using CryptoBase.SpeedTest;
global using CryptoBase.SymmetricCryptos.AEADCryptos;
global using CryptoBase.SymmetricCryptos.BlockCryptoModes;
global using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
global using CryptoBase.SymmetricCryptos.StreamCryptos;
global using System.Collections.Immutable;
global using System.CommandLine;
global using System.Diagnostics;
global using System.Security.Cryptography;

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
methodsArgument.CompletionSources.Add(CryptoList.All);

foreach (string method in CryptoList.Methods)
{
	methodsArgument.CompletionSources.Add(method);
}

Option<double> secondsOption = new(@"--seconds", @"-s")
{
	Description = @"Run benchmarks for num seconds.",
	DefaultValueFactory = _ => 3.0
};

Option<int> bytesOption = new(@"--bytes", @"-b")
{
	Description = @"Run benchmarks on num-byte buffers.",
	DefaultValueFactory = _ => 8 * 1024
};

RootCommand cmd = new()
{
	methodsArgument,
	secondsOption,
	bytesOption
};

cmd.SetAction(parseResult =>
{
	string methods = parseResult.GetRequiredValue(methodsArgument);
	double seconds = parseResult.GetRequiredValue(secondsOption);
	int bytes = parseResult.GetRequiredValue(bytesOption);

	Console.WriteLine(SystemEnvironmentUtils.GetEnvironmentInfo());

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
		using ISymmetricCrypto crypto = CryptoList.GetSymmetricCrypto(realMethod) ?? throw new NotSupportedException($@"{realMethod} is not supported.");

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
			case IBlockModeOneShot blockModeCrypto:
			{
				t.Test(blockModeCrypto);
				break;
			}
			default:
			{
				throw new NotSupportedException($@"{realMethod} is not supported.");
			}
		}
	}
});

return await cmd.Parse(args).InvokeAsync();
