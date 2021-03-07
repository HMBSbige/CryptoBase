using CryptoBase.Abstractions.Digests;
using Org.BouncyCastle.Crypto;
using System;
using System.Buffers;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace CryptoBase.BouncyCastle.Digests
{
	public abstract class BcDigest : IHash
	{
		public abstract string Name { get; }
		public abstract int Length { get; }

		private readonly IDigest _hasher;
		private const int BufferSize = 4096;

		protected BcDigest(IDigest hasher)
		{
			_hasher = hasher;
		}

		public void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Update(origin);
			GetHash(destination);
		}

		public void Update(ReadOnlySpan<byte> source)
		{
			var buffer = ArrayPool<byte>.Shared.Rent(source.Length);
			try
			{
				source.CopyTo(buffer);
				_hasher.BlockUpdate(buffer, 0, source.Length);
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(buffer);
			}
		}

		public void GetHash(Span<byte> destination)
		{
			var outBuffer = ArrayPool<byte>.Shared.Rent(Length);
			try
			{
				_hasher.DoFinal(outBuffer, 0);
				outBuffer.AsSpan(0, Length).CopyTo(destination);
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(outBuffer);
			}
		}

		public void Update(Stream inputStream)
		{
			var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
			try
			{
				int bytesRead;
				while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
				{
					_hasher.BlockUpdate(buffer, 0, bytesRead);
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
					_hasher.BlockUpdate(rented, 0, bytesRead);
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
			_hasher.Reset();
		}
	}
}
