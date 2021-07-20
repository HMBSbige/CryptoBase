using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace CryptoBase.Abstractions.Digests
{
	/// <summary>
	/// 摘要算法接口
	/// </summary>
	public interface IHash : ICanReset, IDisposable
	{
		/// <summary>
		/// 算法名
		/// </summary>
		string Name { get; }

		/// <summary>
		/// Hash 输出长度
		/// </summary>
		int Length { get; }

		/// <summary>
		/// 块大小
		/// </summary>
		int BlockSize { get; }

		void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination);

		void Update(ReadOnlySpan<byte> source);

		void GetHash(Span<byte> destination);

		void Update(Stream inputStream);

		void UpdateFinal(Stream inputStream, Span<byte> destination);

		Task UpdateAsync(Stream inputStream, CancellationToken token = default);

		Task UpdateFinalAsync(Stream inputStream, Memory<byte> destination, CancellationToken token = default);
	}
}
