namespace CryptoBase
{
	public static class Extensions
	{
		public static void Increment(this byte[] nonce)
		{
			for (var i = 0; i < nonce.Length; ++i)
			{
				if (++nonce[i] != 0)
				{
					break;
				}
			}
		}

		public static void IncrementBe(this byte[] counter)
		{
			var j = counter.Length;
			while (--j >= 0 && ++counter[j] == 0)
			{ }
		}
	}
}
