namespace CryptoBase.Tests.Wycheproof;

// Supplies each test of a Wycheproof file as test data.
public sealed class WycheproofVectorsAttribute<T>(string fileName) : DataSourceGeneratorAttribute<T> where T : WycheproofTestVector
{
	protected override IEnumerable<Func<T>> GenerateDataSources(DataGeneratorMetadata dataGeneratorMetadata)
	{
		foreach (T vector in WycheproofVectors.Load<T>(fileName))
		{
			yield return () => vector;
		}
	}
}

// For files whose groups hold what their tests share, such as a key.
public sealed class WycheproofVectorsAttribute<TGroup, T>(string fileName) : DataSourceGeneratorAttribute<T> where TGroup : WycheproofTestGroup<T> where T : WycheproofTestVector
{
	protected override IEnumerable<Func<T>> GenerateDataSources(DataGeneratorMetadata dataGeneratorMetadata)
	{
		foreach (T vector in WycheproofVectors.Load<TGroup, T>(fileName))
		{
			yield return () => vector;
		}
	}
}
