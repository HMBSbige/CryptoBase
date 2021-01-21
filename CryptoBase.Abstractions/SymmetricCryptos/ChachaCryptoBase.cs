namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public abstract class ChachaCryptoBase : StreamCryptoBase
	{
		public const int StateSize = 16; // 64 bytes

		public abstract int IvSize { get; }

		/// <summary>
		/// expand 16-byte k
		/// </summary>
		protected readonly static uint[] Sigma16 = { 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 };

		/// <summary>
		/// expand 32-byte k
		/// </summary>
		protected readonly static uint[] Sigma32 = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
	}
}
