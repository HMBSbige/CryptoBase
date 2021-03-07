using System;
using System.Buffers.Binary;

namespace CryptoBase.Digests.MD5
{
	internal class Fast440MD5Digest : MD5Digest
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
					origin = origin.Slice(SizeOfInt);
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
				BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(4), B);
				BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(8), C);
				BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(12), D);
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
	}
}
