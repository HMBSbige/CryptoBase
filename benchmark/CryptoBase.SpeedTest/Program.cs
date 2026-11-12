using System.CommandLine.Parsing;

#if DEBUG
await Console.Error.WriteLineAsync("On Debug mode");
#endif

if (Debugger.IsAttached)
{
	await Console.Error.WriteLineAsync("Debugger attached!");
}

Argument<string[]> algorithmsArgument = new("algorithm")
{
	HelpName = "algorithm",
	Description = "Algorithms to run: names, patterns with * and ?, group names, or 'all' (the default). Groups and 'all' leave out slow algorithms.",
	Arity = ArgumentArity.ZeroOrMore
};
AddCompletions(algorithmsArgument);
algorithmsArgument.Validators.Add(RejectOptionLikeTokens);

Option<double> secondsOption = new("--seconds", "-s")
{
	Description = "Measuring time of each cell, in seconds.",
	DefaultValueFactory = _ => 0.2,
	CustomParser = result => ParseSeconds(result, allowZero: false)
};

Option<double> warmupOption = new("--warmup", "-w")
{
	Description = "Least warm-up time of each row, or of each operation, in seconds. The warm-up goes on until the JIT, if any, has compiled nothing for a while, up to 5 s longer; 0 skips it.",
	DefaultValueFactory = _ => 0.5,
	CustomParser = result => ParseSeconds(result, allowZero: true)
};

// The parser of --bytes hands the tokens after its sizes on to the algorithm list here.
string[] selectorsAfterSizes = [];

Option<int[]> bytesOption = new("--bytes", "-b")
{
	Description = "Input sizes of the throughput groups, in bytes, with an optional k or m suffix (x1024).",
	HelpName = "size",
	Arity = ArgumentArity.OneOrMore,
	AllowMultipleArgumentsPerToken = true,
	DefaultValueFactory = _ => [16, 64, 256, 1024, 8192, 16384],
	CustomParser = result => ParseSizes(result, out selectorsAfterSizes)
};

Option<bool> decryptOption = new("--decrypt")
{
	Description = "Measure decryption instead of encryption for ciphers that have both."
};

int maximumThreads = 4 * Environment.ProcessorCount;

Option<int> threadsOption = new("--threads", "-t")
{
	Description = $"Threads that each run their own workload at the same time; the rates are their sum. At most {maximumThreads}, four per logical processor.",
	HelpName = "n",
	DefaultValueFactory = _ => 1,
	CustomParser = result => ParseThreads(result, maximumThreads)
};

Option<string> formatOption = new("--format", "-f")
{
	Description = "Output format: text tables, Markdown tables, or a JSON document at the end with progress on standard error.",
	DefaultValueFactory = _ => "text"
};
formatOption.AcceptOnlyFromAmong("text", "markdown", "json");

Option<bool> testOption = new("--test")
{
	Description = "Instead of measuring, check every workload once: each operation, decryption too, at each input size. Ignores --seconds, --warmup, --decrypt, --threads and --format."
};

Argument<string[]> patternsArgument = new("pattern")
{
	HelpName = "pattern",
	Description = "Algorithms to list, selected as for a run. Slow algorithms are listed too.",
	Arity = ArgumentArity.ZeroOrMore
};
AddCompletions(patternsArgument);
patternsArgument.Validators.Add(RejectOptionLikeTokens);

Command listCommand = new("list", "List the algorithms with their groups and operations.")
{
	patternsArgument
};

listCommand.SetAction
(parseResult =>
	{
		string[] patterns = parseResult.GetValue(patternsArgument) ?? [];

		if (!TrySelect(patterns, includeSlow: true, out ImmutableArray<AlgorithmEntry> entries))
		{
			return 1;
		}

		CatalogListing.Write(Console.Out, entries);
		return 0;
	}
);

Command infoCommand = new("info", "Show the runtime, the processor and its instruction sets in full.");

infoCommand.SetAction
(_ =>
	{
		Console.Write(SystemEnvironmentUtils.GetEnvironmentInfo());
		return 0;
	}
);

RootCommand rootCommand = new("Measures the speed of the CryptoBase algorithms.")
{
	algorithmsArgument,
	secondsOption,
	warmupOption,
	bytesOption,
	decryptOption,
	threadsOption,
	formatOption,
	testOption,
	listCommand,
	infoCommand
};

rootCommand.SetAction
(parseResult =>
	{
		ImmutableArray<int> sizes = [.. parseResult.GetRequiredValue(bytesOption)];
		string[] selectors = [.. parseResult.GetValue(algorithmsArgument) ?? [], .. selectorsAfterSizes];

		if (!TrySelect(selectors, includeSlow: false, out ImmutableArray<AlgorithmEntry> entries))
		{
			return 1;
		}

		if (parseResult.GetValue(testOption))
		{
			return SelfTest.Run(entries, sizes, Console.Out) > 0 ? 1 : 0;
		}

		MeasurementSettings settings = new(parseResult.GetRequiredValue(secondsOption), parseResult.GetRequiredValue(warmupOption), parseResult.GetRequiredValue(threadsOption));
		IReporter reporter = parseResult.GetRequiredValue(formatOption) switch
		{
			"text" => new TextReporter(Console.Out),
			"markdown" => new MarkdownReporter(Console.Out),
			"json" => new JsonReporter(Console.OpenStandardOutput(), Console.Error),
			_ => throw new UnreachableException()
		};

		RaisePriority();

		BenchmarkSession session = new(settings, sizes, parseResult.GetValue(decryptOption), reporter);
		return session.Run(entries) > 0 ? 1 : 0;
	}
);

return await rootCommand.Parse(args).InvokeAsync();

static void AddCompletions(Argument argument)
{
	argument.CompletionSources.Add(AlgorithmSelector.AllSelector);

	foreach (AlgorithmGroup group in AlgorithmGroups.All)
	{
		argument.CompletionSources.Add(group.Name);
	}

	foreach (AlgorithmEntry entry in AlgorithmCatalog.Entries)
	{
		argument.CompletionSources.Add(entry.Name);
	}
}

// An unknown option would otherwise reach the algorithm list and be reported as an unknown algorithm.
static void RejectOptionLikeTokens(ArgumentResult result)
{
	foreach (Token token in result.Tokens)
	{
		if (token.Value.StartsWith('-'))
		{
			result.AddError($"Unrecognized option '{token.Value}'.");
		}
	}
}

static bool TrySelect(string[] selectors, bool includeSlow, out ImmutableArray<AlgorithmEntry> entries)
{
	entries = AlgorithmSelector.Select(selectors, includeSlow, out ImmutableArray<string> unmatched);

	foreach (string selector in unmatched)
	{
		Console.Error.WriteLine($"No algorithm or group matches '{selector}'. Run 'list' to see the names.");
	}

	if (!unmatched.IsEmpty)
	{
		return false;
	}

	if (entries.IsEmpty)
	{
		Console.Error.WriteLine("No algorithms are selected: slow algorithms only run when they are named or matched by a wildcard.");
		return false;
	}

	return true;
}

static double ParseSeconds(ArgumentResult result, bool allowZero)
{
	string token = result.Tokens[^1].Value;

	if (!double.TryParse(token, NumberStyles.Float, CultureInfo.InvariantCulture, out double seconds) || !double.IsFinite(seconds) || seconds < 0 || seconds is 0 && !allowZero)
	{
		string option = result.Parent is OptionResult { Option.Name: var name } ? name : "--seconds";
		result.AddError($"Option '{option}' takes a finite number of seconds {(allowZero ? "of 0 or more" : "greater than 0")}; '{token}' is not one.");
	}

	return seconds;
}

static int ParseThreads(ArgumentResult result, int maximum)
{
	string token = result.Tokens[^1].Value;

	if (!int.TryParse(token, NumberStyles.None, CultureInfo.InvariantCulture, out int threads) || threads < 1 || threads > maximum)
	{
		result.AddError($"Option '--threads' takes a number of threads from 1 to {maximum}; '{token}' is not one.");
	}

	return threads;
}

// Takes sizes until a token that is not a number, which goes with the rest to the algorithm list, so that '-b 16 1k aes-*' works.
// ArgumentResult.OnlyTake would give the rest back to the parser, but it does not support the argument of an option.
static int[] ParseSizes(ArgumentResult result, out string[] selectors)
{
	const int MaximumSize = 256 << 20;
	List<int> sizes = [];
	selectors = [];

	for (int i = 0; i < result.Tokens.Count; ++i)
	{
		string token = result.Tokens[i].Value;

		if (TryParseSize(token, out int size) && size <= MaximumSize)
		{
			if (!sizes.Contains(size))
			{
				sizes.Add(size);
			}

			continue;
		}

		if (i is 0 || char.IsAsciiDigit(token[0]) || token[0] is '-' or '+' or '.')
		{
			result.AddError($"Option '--bytes' takes sizes from 1 to {MaximumSize} bytes, such as 16, 1k or 1m; '{token}' is not one.");
			return [];
		}

		selectors = [.. result.Tokens.Skip(i).Select(static token => token.Value)];
		break;
	}

	return [.. sizes];
}

static bool TryParseSize(string token, out int size)
{
	long multiplier = 1;
	ReadOnlySpan<char> digits = token;

	if (digits.Length > 0 && char.ToLowerInvariant(digits[^1]) is 'k' or 'm')
	{
		multiplier = char.ToLowerInvariant(digits[^1]) is 'k' ? 1024 : 1024 * 1024;
		digits = digits.Slice(0, digits.Length - 1);
	}

	if (long.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out long value) && value > 0 && value <= int.MaxValue / multiplier)
	{
		size = (int)(value * multiplier);
		return true;
	}

	size = 0;
	return false;
}

static void RaisePriority()
{
	try
	{
		using Process process = Process.GetCurrentProcess();
		process.PriorityClass = ProcessPriorityClass.High;
	}
	catch (Exception)
	{
		// A higher priority only steadies the results; run without it where it is not allowed.
	}
}
