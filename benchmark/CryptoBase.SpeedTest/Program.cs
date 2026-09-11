#if DEBUG
await Console.Error.WriteLineAsync(@"On Debug mode");
#endif

if (Debugger.IsAttached)
{
	await Console.Error.WriteLineAsync(@"Debugger attached!");
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
secondsOption.Validators.Add
(result =>
	{
		if (result.Tokens.Count is 0)
		{
			return;
		}

		if (!double.TryParse(result.Tokens[^1].Value, out double seconds)
			|| !double.IsFinite(seconds)
			|| seconds < CryptoTest.MinimumSeconds)
		{
			result.AddError($@"Option '--seconds' must be a finite number greater than or equal to {CryptoTest.MinimumSeconds}.");
		}
	}
);

Option<int> bytesOption = new(@"--bytes", @"-b")
{
	Description = @"Run benchmarks on num-byte buffers.",
	DefaultValueFactory = _ => 8 * 1024
};
bytesOption.Validators.Add
(result =>
	{
		if (result.Tokens.Count is 0)
		{
			return;
		}

		if (!int.TryParse(result.Tokens[^1].Value, out int bytes) || bytes <= 0)
		{
			result.AddError(@"Option '--bytes' must be greater than 0.");
		}
	}
);

methodsArgument.Validators.Add
(result =>
	{
		if (result.Parent is not { } commandResult)
		{
			return;
		}

		if (commandResult.GetResult(bytesOption) is not { } bytesResult || bytesResult.Errors.Any())
		{
			return;
		}

		int bytes = bytesResult.GetValueOrDefault<int>();

		if (bytes is <= 0 or >= 16)
		{
			return;
		}

		string methods = result.GetValueOrDefault<string>();
		IEnumerable<string> methodList = GetMethodList(methods);

		if (methodList.Any
			(method =>
				string.Equals(method, CryptoList.Aes128Xts, StringComparison.OrdinalIgnoreCase)
				|| string.Equals(method, CryptoList.Aes256Xts, StringComparison.OrdinalIgnoreCase)
			))
		{
			result.AddError(@"XTS benchmarks require '--bytes' to be at least 16.");
		}
	}
);

RootCommand cmd = new()
{
	methodsArgument,
	secondsOption,
	bytesOption
};

cmd.SetAction
(parseResult =>
	{
		string methods = parseResult.GetRequiredValue(methodsArgument);
		double seconds = parseResult.GetRequiredValue(secondsOption);
		int bytes = parseResult.GetRequiredValue(bytesOption);

		Console.WriteLine(SystemEnvironmentUtils.GetEnvironmentInfo());

		Console.WriteLine($@"Seconds: {seconds}s");
		Console.WriteLine($@"Buffer size: {bytes} bytes");

		try
		{
			using Process process = Process.GetCurrentProcess();
			process.PriorityClass = ProcessPriorityClass.RealTime;
		}
		catch (Exception)
		{
			Console.WriteLine(@"Warning: failed to raise process priority!");
		}

		Console.WriteLine();

		IEnumerable<string> methodList = GetMethodList(methods);

		foreach (string method in methodList)
		{
			string realMethod = method.ToLowerInvariant();
			using ISymmetricCrypto crypto = CryptoList.GetSymmetricCrypto(realMethod) ?? throw new NotSupportedException($@"{realMethod} is not supported.");

			GC.Collect();
			GC.WaitForPendingFinalizers();
			GC.Collect();

			Console.Write($@"Testing {realMethod}: ");

			CryptoTest t = new(bytes, seconds);

			switch (crypto)
			{
				case IStreamCrypto streamCrypto:
				{
					t.Test(streamCrypto);
					break;
				}
				case IAeadCrypto aeadCrypto:
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
	}
);

return await cmd.Parse(args).InvokeAsync();

static IEnumerable<string> GetMethodList(string methods)
{
	string[] methodList = methods.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

	return methodList.Contains(CryptoList.All, StringComparer.OrdinalIgnoreCase)
		? CryptoList.Methods
		: methodList;
}
