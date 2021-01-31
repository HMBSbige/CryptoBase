namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public interface IStreamCrypto : ISymmetricCrypto
	{
		/// <summary>
		/// 重置状态
		/// </summary>
		void Reset();
	}
}
