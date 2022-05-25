namespace CryptoBase.SpeedTest;

internal class CryptoTest
{
	public static ReadOnlySpan<byte> Key => new byte[]
	{
		0, 1, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23,
		24, 25, 26, 27, 28, 29, 30, 31
	};

	public static ReadOnlySpan<byte> IV => new byte[]
	{
		0, 1, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23,
		24, 25, 26, 27, 28, 29, 30, 31
	};

	private readonly int _step;
	private readonly double _duration;

	public CryptoTest(int step, double duration)
	{
		_step = step;
		_duration = duration;
	}

	public void Test(IStreamCrypto crypto)
	{
		Span<byte> o = new byte[_step];
		ulong length = 0ul;
		double totalSeconds = 0.0;

		do
		{
			ReadOnlySpan<byte> i = RandomNumberGenerator.GetBytes(_step);
			Stopwatch sw = Stopwatch.StartNew();
			crypto.Update(i, o);
			sw.Stop();
			totalSeconds += sw.Elapsed.TotalSeconds;
			++length;
		} while (totalSeconds < _duration);

		crypto.Dispose();

		double result = length * (ulong)_step / totalSeconds / 1024.0 / 1024.0;
		Console.WriteLine($@"{result:F2} MB/s");
	}

	public void Test(IAEADCrypto crypto, int nonceLength = 12)
	{
		Span<byte> o = new byte[_step];
		ReadOnlySpan<byte> nonce = IV[..nonceLength];
		Span<byte> tag = stackalloc byte[16];
		ulong length = 0ul;
		double totalSeconds = 0.0;

		do
		{
			ReadOnlySpan<byte> i = RandomNumberGenerator.GetBytes(_step);
			Stopwatch sw = Stopwatch.StartNew();
			crypto.Encrypt(nonce, i, o, tag);
			sw.Stop();
			totalSeconds += sw.Elapsed.TotalSeconds;
			++length;
		} while (totalSeconds < _duration);

		crypto.Dispose();

		double result = length * (ulong)_step / totalSeconds / 1024.0 / 1024.0;
		Console.WriteLine($@"{result:F2} MB/s");
	}
}
