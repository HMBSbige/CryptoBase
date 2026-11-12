using System.IO.Enumeration;

namespace CryptoBase.SpeedTest.Catalog;

/// <summary>
/// Resolves the algorithm selectors of the command line against the catalog.
/// </summary>
/// <remarks>
/// A selector is, case-insensitively, <c>all</c>, a group name, a pattern with <c>*</c> and <c>?</c>, or an algorithm name.
/// <c>all</c> and group names leave out slow algorithms; patterns and names do not.
/// </remarks>
internal static class AlgorithmSelector
{
	public const string AllSelector = "all";

	/// <summary>
	/// Selects the entries that <paramref name="selectors" /> name, in catalog order and without duplicates.
	/// </summary>
	/// <param name="selectors">The selectors; none selects <c>all</c>.</param>
	/// <param name="includeSlow">Whether <c>all</c> and group names also select slow algorithms.</param>
	/// <param name="unmatched">The selectors that match nothing.</param>
	public static ImmutableArray<AlgorithmEntry> Select(IReadOnlyCollection<string> selectors, bool includeSlow, out ImmutableArray<string> unmatched)
	{
		ImmutableArray<AlgorithmEntry> entries = AlgorithmCatalog.Entries;

		if (selectors.Count is 0)
		{
			unmatched = [];
			return [.. entries.Where(entry => includeSlow || !entry.IsSlow)];
		}

		HashSet<AlgorithmEntry> selected = [];
		ImmutableArray<string>.Builder missing = ImmutableArray.CreateBuilder<string>();

		foreach (string selector in selectors)
		{
			bool matched = false;

			foreach (AlgorithmEntry entry in entries)
			{
				if (Matches(selector, entry, includeSlow, out bool matchedGroup))
				{
					selected.Add(entry);
					matched = true;
				}

				matched |= matchedGroup;
			}

			if (!matched)
			{
				missing.Add(selector);
			}
		}

		unmatched = missing.DrainToImmutable();
		return [.. entries.Where(selected.Contains)];
	}

	private static bool Matches(string selector, AlgorithmEntry entry, bool includeSlow, out bool matchedGroup)
	{
		if (selector.Equals(AllSelector, StringComparison.OrdinalIgnoreCase) || selector.Equals(entry.Group.Name, StringComparison.OrdinalIgnoreCase))
		{
			// A group of only slow algorithms still names something.
			matchedGroup = true;
			return includeSlow || !entry.IsSlow;
		}

		matchedGroup = false;

		return selector.AsSpan().IndexOfAny('*', '?') >= 0
			? FileSystemName.MatchesSimpleExpression(selector, entry.Name)
			: selector.Equals(entry.Name, StringComparison.OrdinalIgnoreCase);
	}
}
