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
		public int Length => _hasher.HashLengthInBytes;
		public abstract int BlockSize { get; }

		private readonly IncrementalHash _hasher;
		private const int BufferSize = 4096;

		protected DefaultDigest(HashAlgorithmName name)
		{
			_hasher = IncrementalHash.CreateHash(name);
		}

		public void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			_hasher.AppendData(origin);
			_hasher.GetHashAndReset(destination);
		}

		public void Update(ReadOnlySpan<byte> source)
		{
			_hasher.AppendData(source);
		}

		public void GetHash(Span<byte> destination)
		{
			_hasher.GetHashAndReset(destination);
		}

		public void Update(Stream inputStream)
		{
			var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
			try
			{
				int bytesRead;
				while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
				{
					_hasher.AppendData(buffer.AsSpan(0, bytesRead));
				}
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(buffer);
			}
		}

		public void UpdateFinal(Stream inputStream, Span<byte> destination)
		{
			Update(inputStream);
			GetHash(destination);
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
					_hasher.AppendData(rented.AsSpan(0, bytesRead));
				}
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(rented);
			}
		}

		public async Task UpdateFinalAsync(Stream inputStream, Memory<byte> destination, CancellationToken token = default)
		{
			await UpdateAsync(inputStream, token).ConfigureAwait(false);
			GetHash(destination.Span);
		}

		public void Reset()
		{
			Span<byte> destination = stackalloc byte[Length];
			GetHash(destination);
		}

		public void Dispose()
		{
			_hasher.Dispose();
			GC.SuppressFinalize(this);
		}
	}
}
