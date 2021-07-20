using CryptoBase.Abstractions.Digests;
using System;
using System.Buffers;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace CryptoBase.Digests
{
	public abstract class DefaultDigest : IHash
	{
		public abstract string Name { get; }
		public abstract int Length { get; }
		public abstract int BlockSize { get; }

		private readonly HashAlgorithm _hasher;
		private const int BufferSize = 4096;

		protected DefaultDigest(HashAlgorithm hasher)
		{
			_hasher = hasher;
		}

		public void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			_hasher.TryComputeHash(origin, destination, out _);
		}

		public void Update(ReadOnlySpan<byte> source)
		{
			var buffer = ArrayPool<byte>.Shared.Rent(source.Length);
			try
			{
				source.CopyTo(buffer);
				_hasher.TransformBlock(buffer, 0, source.Length, default, default);
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(buffer);
			}
		}

		public void GetHash(Span<byte> destination)
		{
			UpdateFinal(Array.Empty<byte>(), destination);
		}

		public void Update(Stream inputStream)
		{
			var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
			try
			{
				int bytesRead;
				while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
				{
					_hasher.TransformBlock(buffer, 0, bytesRead, default, default);
				}
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(buffer);
			}
		}

		public void UpdateFinal(Stream inputStream, Span<byte> destination)
		{
			_hasher.ComputeHash(inputStream).CopyTo(destination);
		}

		public async Task UpdateAsync(Stream inputStream, CancellationToken token = default)
		{
			var rented = ArrayPool<byte>.Shared.Rent(BufferSize);
			try
			{
				Memory<byte> buffer = rented;

				int bytesRead;
				while ((bytesRead = await inputStream.ReadAsync(buffer, token).ConfigureAwait(false)) > 0)
				{
					_hasher.TransformBlock(rented, 0, bytesRead, default, default);
				}
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(rented);
			}
		}

		public async Task UpdateFinalAsync(Stream inputStream, Memory<byte> destination, CancellationToken token = default)
		{
			var buffer = await _hasher.ComputeHashAsync(inputStream, token).ConfigureAwait(false);
			buffer.CopyTo(destination);
		}

		public void Reset()
		{
			_hasher.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
		}

		public void Dispose()
		{
			_hasher.Dispose();
			GC.SuppressFinalize(this);
		}
	}
}
