namespace CryptoBase.SpeedTest;

internal class CryptoTest(int step, double duration)
{
	public static ReadOnlySpan<byte> Key =>
	[
		0, 1, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23,
		24, 25, 26, 27, 28, 29, 30, 31
	];

	public static ReadOnlySpan<byte> IV =>
	[
		0, 1, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23,
		24, 25, 26, 27, 28, 29, 30, 31
	];

	public void Test(IStreamCrypto crypto)
	{
		Span<byte> o = new byte[step];
		ulong length = 0ul;
		double totalSeconds = 0.0;

		ReadOnlySpan<byte> random = RandomNumberGenerator.GetBytes(step);

		do
		{
			Span<byte> i = GC.AllocateUninitializedArray<byte>(random.Length);
			random.CopyTo(i);
			Stopwatch sw = Stopwatch.StartNew();

			crypto.Update(i, o);

			sw.Stop();
			totalSeconds += sw.Elapsed.TotalSeconds;
			++length;
		} while (totalSeconds < duration);

		crypto.Dispose();

		double result = length * (ulong)step / totalSeconds / 1024.0 / 1024.0;
		Console.WriteLine($@"{result:F2} MiB/s");
	}

	public void Test(IAEADCrypto crypto, int nonceLength = 12)
	{
		Span<byte> o = new byte[step];
		ReadOnlySpan<byte> nonce = IV[..nonceLength];
		Span<byte> tag = stackalloc byte[16];
		ulong length = 0ul;
		double totalSeconds = 0.0;

		ReadOnlySpan<byte> random = RandomNumberGenerator.GetBytes(step);

		do
		{
			Span<byte> i = GC.AllocateUninitializedArray<byte>(random.Length);
			random.CopyTo(i);
			Stopwatch sw = Stopwatch.StartNew();

			crypto.Encrypt(nonce, i, o, tag);

			sw.Stop();
			totalSeconds += sw.Elapsed.TotalSeconds;
			++length;
		} while (totalSeconds < duration);

		crypto.Dispose();

		double result = length * (ulong)step / totalSeconds / 1024.0 / 1024.0;
		Console.WriteLine($@"{result:F2} MiB/s");
	}
}
