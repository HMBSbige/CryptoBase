using Org.BouncyCastle.Crypto;

namespace CryptoBase.BouncyCastle;

internal static class Check
{
	internal static void DataLength(byte[] buf, int off, int len, string msg)
	{
		if (off > buf.Length - len)
		{
			throw new DataLengthException(msg);
		}
	}

	internal static void OutputLength(byte[] buf, int off, int len, string msg)
	{
		if (off > buf.Length - len)
		{
			throw new OutputLengthException(msg);
		}
	}
}
