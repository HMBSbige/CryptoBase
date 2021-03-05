using System;
using System.Buffers.Binary;

namespace CryptoBase.Digests.MD5
{
	internal class Fast440MD5Digest : MD5Digest
	{
		public override void UpdateFinal(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			if (origin.Length > 55)
			{
				throw new ArgumentException(@"message is too long!", nameof(origin));
			}
			try
			{
				var t = origin;

				var index = 0;
				while (t.Length >= SizeOfInt)
				{
					X[index++] = BinaryPrimitives.ReadUInt32LittleEndian(t);
					t = t.Slice(SizeOfInt);
				}

				const uint padding = 0b10000000;
				X[index++] = t.Length switch
				{
					0 => padding,
					1 => t[0] | padding << 8,
					2 => t[0] | (uint)t[1] << 8 | padding << 16,
					3 => t[0] | (uint)t[1] << 8 | (uint)t[2] << 16 | padding << 24,
					_ => 0 // unreachable
				};

				//final

				for (var i = index; i < 14; ++i)
				{
					X[i] = 0;
				}

				X[14] = (uint)origin.Length << 3;
				X[15] = 0;

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
