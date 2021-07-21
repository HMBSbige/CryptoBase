using System;
using System.Buffers.Binary;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace CryptoBase.Digests.MD5
{
	public class Fast440MD5Digest : MD5Digest
	{
		public override void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			if (origin.Length > 55)
			{
				throw new ArgumentException(@"message is too long!", nameof(origin));
			}
			try
			{
				X.AsSpan(0, BlockSizeOfInt).Clear();
				X[14] = (uint)origin.Length << 3;

				var index = 0;
				while (origin.Length >= SizeOfInt)
				{
					X[index++] = BinaryPrimitives.ReadUInt32LittleEndian(origin);
					origin = origin[SizeOfInt..];
				}

				const uint padding = 0b10000000;
				X[index] = origin.Length switch
				{
					0 => padding,
					1 => origin[0] | padding << 8,
					2 => origin[0] | (uint)origin[1] << 8 | padding << 16,
					3 => origin[0] | (uint)origin[1] << 8 | (uint)origin[2] << 16 | padding << 24,
					_ => throw new InvalidOperationException(@"unreachable code!!!")
				};

				Process();

				BinaryPrimitives.WriteUInt32LittleEndian(destination, A);
				BinaryPrimitives.WriteUInt32LittleEndian(destination[4..], B);
				BinaryPrimitives.WriteUInt32LittleEndian(destination[8..], C);
				BinaryPrimitives.WriteUInt32LittleEndian(destination[12..], D);
			}
			finally
			{
				Reset();
			}
		}

		public override void Update(ReadOnlySpan<byte> source)
		{
			throw new NotSupportedException();
		}

		public override void GetHash(Span<byte> destination)
		{
			throw new NotSupportedException();
		}

		public override void Update(Stream inputStream)
		{
			throw new NotSupportedException();
		}

		public override void UpdateFinal(Stream inputStream, Span<byte> destination)
		{
			throw new NotSupportedException();
		}

		public override Task UpdateAsync(Stream inputStream, CancellationToken token = default)
		{
			throw new NotSupportedException();
		}

		public override Task UpdateFinalAsync(Stream inputStream, Memory<byte> destination, CancellationToken token = default)
		{
			throw new NotSupportedException();
		}
	}
}
