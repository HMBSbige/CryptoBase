using CryptoBase;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.AEADCryptos;
using CryptoBase.SymmetricCryptos.AEADCryptos.GCM;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace UnitTest
{
	[TestClass]
	public class AESGCMTest
	{
		private static void Test(IAEADCrypto crypto, string nonceHex, string associatedDataHex, string tagHex, string plainHex, string cipherHex)
		{
			Assert.AreEqual(@"AES-GCM", crypto.Name);

			ReadOnlySpan<byte> nonce = nonceHex.FromHex();
			ReadOnlySpan<byte> associatedData = associatedDataHex.FromHex();
			ReadOnlySpan<byte> tag = tagHex.FromHex();
			ReadOnlySpan<byte> plain = plainHex.FromHex();
			ReadOnlySpan<byte> cipher = cipherHex.FromHex();
			Span<byte> o1 = stackalloc byte[plain.Length];
			Span<byte> o2 = stackalloc byte[16];

			crypto.Encrypt(nonce, plain, o1, o2, associatedData);
			Assert.IsTrue(o1.SequenceEqual(cipher));
			Assert.IsTrue(o2.SequenceEqual(tag));

			crypto.Encrypt(nonce, plain, o1, o2, associatedData);
			Assert.IsTrue(o1.SequenceEqual(cipher));
			Assert.IsTrue(o2.SequenceEqual(tag));

			crypto.Decrypt(nonce, cipher, tag, o1, associatedData);
			Assert.IsTrue(o1.SequenceEqual(plain));

			crypto.Decrypt(nonce, cipher, tag, o1, associatedData);
			Assert.IsTrue(o1.SequenceEqual(plain));

			crypto.Dispose();
		}

		/// <summary>
		/// https://gchq.github.io/CyberChef/#recipe=AES_Encrypt(%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D,'GCM','Hex','Hex','')
		/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
		/// </summary>
		[TestMethod]
		[DataRow(@"00000000000000000000000000000000", @"000000000000000000000000", @"",
			@"58e2fccefa7e3061367f1d57a4e7455a",
			@"",
			@"")]
		[DataRow(@"00000000000000000000000000000000", @"000000000000000000000000", @"",
			@"ab6e47d42cec13bdf53a67b21257bddf",
			@"00000000000000000000000000000000",
			@"0388dace60b6a392f328c2b971b2fe78")]
		[DataRow(@"feffe9928665731c6d6a8f9467308308", @"cafebabefacedbaddecaf888", @"",
			@"4d5c2af327cd64a62cf35abd2ba6fab4",
			@"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
			@"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985")]
		[DataRow(@"feffe9928665731c6d6a8f9467308308", @"cafebabefacedbaddecaf888", @"feedfacedeadbeeffeedfacedeadbeefabaddad2",
			@"5bc94fbc3221a5db94fae95ae7121a47",
			@"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
			@"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091")]
		[DataRow(@"000000000000000000000000000000000000000000000000", @"000000000000000000000000", @"",
			@"cd33b28ac773f74ba00ed1f312572435",
			@"",
			@"")]
		[DataRow(@"000000000000000000000000000000000000000000000000", @"000000000000000000000000", @"",
				@"2ff58d80033927ab8ef4d4587514f0fb",
				@"00000000000000000000000000000000",
				@"98e7247c07f0fe411c267e4384b0f600")]
		[DataRow(@"feffe9928665731c6d6a8f9467308308feffe9928665731c", @"cafebabefacedbaddecaf888", @"",
				@"9924a7c8587336bfb118024db8674a14",
				@"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
				@"3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256")]
		[DataRow(@"feffe9928665731c6d6a8f9467308308feffe9928665731c", @"cafebabefacedbaddecaf888", @"feedfacedeadbeeffeedfacedeadbeefabaddad2",
				@"2519498e80f1478f37ba55bd6d27618c",
				@"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
				@"3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710")]
		[DataRow(@"0000000000000000000000000000000000000000000000000000000000000000", @"000000000000000000000000", @"",
				@"530f8afbc74536b9a963b4f1c4cb738b",
				@"",
				@"")]
		[DataRow(@"0000000000000000000000000000000000000000000000000000000000000000", @"000000000000000000000000", @"",
				@"d0d1c8a799996bf0265b98b5d48ab919",
				@"00000000000000000000000000000000",
				@"cea7403d4d606b6e074ec5d3baf39d18")]
		[DataRow(@"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", @"cafebabefacedbaddecaf888", @"",
				@"b094dac5d93471bdec1a502270e3cc6c",
				@"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
				@"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad")]
		[DataRow(@"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", @"cafebabefacedbaddecaf888", @"feedfacedeadbeeffeedfacedeadbeefabaddad2",
				@"76fc6ece0f4e1768cddf8853bb2d551b",
				@"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
				@"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662")]
		[DataRow(@"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", @"cafebabefacedbaddecaf888", @"",
				@"82b7513a7a7b7433b3565b5fc4368e5d",
				@"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015add9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255eeb4f0117db250247e91f81d25ac0e222e6b45be50313afc228ed21c1cad5fd37041f5dcc10b200af6a52860907ef5b388a907313de0071b4c25ebc7f57dd27f012d17315e830a47082b82754974ccdf116971be4d37d12d64e28d8b4442f0e8a9c2197136ae40aa1a2272edb74aef745686d68bb48f7bd93a0faec65e1ae618d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255bd9e497318697bafedcc87d8590dc6755a3947e7fe225ed3753b2debd2f593877bc7981d8f1c9a207a90d3593991788831e4844ac4c6e298145050960f263606522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015add9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
				@"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255bd9e497318697bafedcc87d8590dc6755a3947e7fe225ed3753b2debd2f593877bc7981d8f1c9a207a90d3593991788831e4844ac4c6e298145050960f263606522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015add9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255a44be0b0235f0e6a6c150579976e5023087a94adec71e6bbfd2f02b3d6264bc4afc0239f915971bab03d6c762e7a61dc0defc46fc441c3c9c2819145b31663bef81580218e3a1634ee3721643ed34120f4ce389bfa4a9e1a967cb1d0f4d1dcd55ec486f385da3a3879bdbce2b3b8d0a443a929b6861ebe1b092f52d017ef44c3171117604c7e0d758e5dc70fd58d1b6eb3dc2b28dd70c9f282318b5c0188d8de4ec42ea9caa9f65c2e95f195e3a78e6363ee464a576e5991e9fb238a15228d4fc6c5a72013585de332fd43918f0c7287d9b874e982947d5b8c059a28a14c0f3c635c9a1b92c46e2756cf627eab6ad392ad1f8c23375596cb9861af3f1634ac7e")]
		public void Test(string keyHex, string nonceHex, string associatedDataHex, string tagHex, string plainHex, string cipherHex)
		{
			var key = keyHex.FromHex();
			Test(new DefaultAesGcmCrypto(key), nonceHex, associatedDataHex, tagHex, plainHex, cipherHex);
			Test(new BcAesGcmCrypto(key), nonceHex, associatedDataHex, tagHex, plainHex, cipherHex);
			Test(new GcmCryptoMode(AESUtils.CreateECB(key)), nonceHex, associatedDataHex, tagHex, plainHex, cipherHex);
			Test(AEADCryptoCreate.AesGcm(key), nonceHex, associatedDataHex, tagHex, plainHex, cipherHex);
		}
	}
}
