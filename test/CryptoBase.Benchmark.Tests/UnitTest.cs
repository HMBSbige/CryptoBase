namespace CryptoBase.Benchmark.Tests;

public class UnitTest
{
	[Fact]
	public void EnvironmentTest()
	{
		Console.WriteLine(SystemEnvironmentUtils.GetEnvironmentInfo());
	}
}
