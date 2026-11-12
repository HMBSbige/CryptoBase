namespace CryptoBase.SpeedTest.Reporting;

internal static class CatalogListing
{
	public static void Write(TextWriter writer, ImmutableArray<AlgorithmEntry> entries)
	{
		const string NameTitle = "algorithm";
		const string GroupTitle = "group";
		const string UnitTitle = "unit";
		const string OperationsTitle = "operations";

		int nameWidth = Math.Max(NameTitle.Length, entries.Max(static entry => entry.Name.Length));
		int groupWidth = Math.Max(GroupTitle.Length, entries.Max(static entry => entry.Group.Name.Length));
		string[] operations = [.. entries.Select(static entry => string.Join(' ', entry.Operations))];
		int operationsWidth = Math.Max(OperationsTitle.Length, operations.Max(static text => text.Length));

		writer.WriteLine($"{NameTitle.PadRight(nameWidth)}  {GroupTitle.PadRight(groupWidth)}  {UnitTitle,-5}  {OperationsTitle.PadRight(operationsWidth)}  notes".TrimEnd());

		for (int i = 0; i < entries.Length; ++i)
		{
			AlgorithmEntry entry = entries[i];
			string unit = entry.Metric switch
			{
				Metric.Throughput => "MiB/s",
				Metric.Operations => "ops/s",
				_ => throw new UnreachableException()
			};

			writer.WriteLine($"{entry.Name.PadRight(nameWidth)}  {entry.Group.Name.PadRight(groupWidth)}  {unit,-5}  {operations[i].PadRight(operationsWidth)}  {GetNotes(entry)}".TrimEnd());
		}
	}

	private static string GetNotes(AlgorithmEntry entry)
	{
		List<string> notes = [];

		if (entry.IsSlow)
		{
			notes.Add("slow: runs only when named or matched by a wildcard");
		}

		if (entry.Notes is { } text)
		{
			notes.Add(text);
		}

		if (entry.InputSizeMultiple > 1)
		{
			notes.Add(FormattableString.Invariant($"input a multiple of {entry.InputSizeMultiple} bytes"));
		}
		else if (entry.MinimumInputSize > 0)
		{
			notes.Add(FormattableString.Invariant($"input at least {entry.MinimumInputSize} bytes"));
		}

		if (entry.MaximumInputSize < int.MaxValue)
		{
			notes.Add(FormattableString.Invariant($"input at most {entry.MaximumInputSize} bytes"));
		}

		return string.Join("; ", notes);
	}
}
