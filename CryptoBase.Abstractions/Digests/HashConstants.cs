namespace CryptoBase.Abstractions.Digests
{
	public static class HashConstants
	{
		public const int Md5Length = 16;
		public const int Sha1Length = 20;
		public const int SM3Length = 32;
		public const int Sha256Length = 32;
		public const int Sha384Length = 48;
		public const int Sha512Length = 64;

		public const int Md5BlockSize = 64;
		public const int Sha1BlockSize = 64;
		public const int SM3BlockSize = 64;
		public const int Sha256BlockSize = 64;
		public const int Sha384BlockSize = 128;
		public const int Sha512BlockSize = 128;
	}
}
