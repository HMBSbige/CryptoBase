using CryptoBase.Abstractions.Hashes;
using CryptoBase.Abstractions.Macs;
using CryptoBase.Hashes.MD5;
using CryptoBase.Hashes.Sha1;
using CryptoBase.Hashes.Sha224;
using CryptoBase.Hashes.Sha256;
using CryptoBase.Hashes.Sha384;
using CryptoBase.Hashes.Sha512;
using CryptoBase.Hashes.SM3;
using CryptoBase.Macs.Hmac;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using static CryptoBase.Tests.Macs.MacAlgorithmTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Macs.Hmac;

/// <summary>
/// HMAC vectors based on RFC 2202 and RFC 4231, with independently verified extensions for SM3 and untruncated results.
/// </summary>
[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class HmacTest
{
	[Test]
	[Arguments(@"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", @"4869205468657265", @"51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70")]
	[Arguments(@"4a656665", @"7768617420646f2079612077616e7420666f72206e6f7468696e673f", @"2e87f1d16862e6d964b50a5200bf2b10b764faa9680a296a2405f24bec39f882")]
	[Arguments(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", @"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", @"dd9421e1c725bdf52ec1aa34edadb3c97f5951a83a2fa93f73a7902bc1dcc777")]
	[Arguments(@"0102030405060708090a0b0c0d0e0f10111213141516171819", @"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", @"b57c79be03472aeb8cada581dea332cb2ba83d19cb1b052dd07194def75fb8cd")]
	[Arguments(@"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", @"546573742057697468205472756e636174696f6e", @"f68127c9f91764f5fb820d537adc8330d3aa6ccc0016575fe3975bfe8d522ecb")]
	[Arguments(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", @"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", @"b4fd844e13342002f0b2e0690ea7741f1497d993a70494cea601e657bedf67a0")]
	[Arguments(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", @"5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e", @"5acbdeb0c8c1ef3a99088fe51c0a1d5f4e1c175935f016aee74eb8056db18acb")]
	public async Task TestSM3(string keyStr, string messageHex, string expected)
	{
		await VerifyVector<HmacAlgorithm<SM3HashAlgorithm>>(keyStr, messageHex, expected);
	}

	[Test]
	[Arguments(@"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", @"4869205468657265", @"5ccec34ea9656392457fa1ac27f08fbc")]
	[Arguments(@"4a656665", @"7768617420646f2079612077616e7420666f72206e6f7468696e673f", @"750c783e6ab0b503eaa86e310a5db738")]
	[Arguments(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", @"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", @"2ab8b9a9f7d3894d15ad8383b97044b2")]
	[Arguments(@"0102030405060708090a0b0c0d0e0f10111213141516171819", @"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", @"697eaf0aca3a3aea3a75164746ffaa79")]
	[Arguments(@"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", @"546573742057697468205472756e636174696f6e", @"951726cea438b8e106e43b3d87a19c8e")]
	[Arguments(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", @"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", @"bfecaf4efff90a3a668f3922fec3762d")]
	[Arguments(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", @"5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e", @"09b8ae7b15adbbb243aca3491b51512b")]
	public async Task TestMd5(string keyStr, string messageHex, string expected)
	{
		await VerifyVector<HmacAlgorithm<MD5HashAlgorithm>>(keyStr, messageHex, expected);
	}

	[Test]
	[Arguments(@"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", @"4869205468657265", @"b617318655057264e28bc0b6fb378c8ef146be00")]
	[Arguments(@"4a656665", @"7768617420646f2079612077616e7420666f72206e6f7468696e673f", @"effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")]
	[Arguments(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", @"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", @"125d7342b9ac11cd91a39af48aa17b4f63f175d3")]
	[Arguments(@"0102030405060708090a0b0c0d0e0f10111213141516171819", @"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", @"4c9007f4026250c6bc8414f9bf50c86c2d7235da")]
	[Arguments(@"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", @"546573742057697468205472756e636174696f6e", @"4c1a03424b55e07fe7f27be1d58bb9324a9a5a04")]
	[Arguments(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", @"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", @"90d0dace1c1bdc957339307803160335bde6df2b")]
	[Arguments(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", @"5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e", @"217e44bb08b6e06a2d6c30f3cb9f537f97c63356")]
	public async Task TestSha1(string keyStr, string messageHex, string expected)
	{
		await VerifyVector<HmacAlgorithm<Sha1HashAlgorithm>>(keyStr, messageHex, expected);
	}

	[Test]
	[Arguments(@"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", @"4869205468657265", @"896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22")]
	[Arguments(@"4a656665", @"7768617420646f2079612077616e7420666f72206e6f7468696e673f", @"a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44")]
	[Arguments(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", @"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", @"7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea")]
	[Arguments(@"0102030405060708090a0b0c0d0e0f10111213141516171819", @"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", @"6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a")]
	[Arguments(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", @"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", @"95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e")]
	[Arguments(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", @"5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e", @"3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1")]
	public async Task TestSha224(string keyStr, string messageHex, string expected)
	{
		await VerifyVector<HmacAlgorithm<Sha224HashAlgorithm>>(keyStr, messageHex, expected);
	}

	[Test]
	[Arguments(@"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", @"4869205468657265", @"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")]
	[Arguments(@"4a656665", @"7768617420646f2079612077616e7420666f72206e6f7468696e673f", @"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")]
	[Arguments(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", @"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", @"773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")]
	[Arguments(@"0102030405060708090a0b0c0d0e0f10111213141516171819", @"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", @"82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b")]
	[Arguments(@"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", @"546573742057697468205472756e636174696f6e", @"a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5")]
	[Arguments(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", @"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", @"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")]
	[Arguments(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", @"5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e", @"9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2")]
	public async Task TestSha256(string keyStr, string messageHex, string expected)
	{
		await VerifyVector<HmacAlgorithm<Sha256HashAlgorithm>>(keyStr, messageHex, expected);
	}

	[Test]
	[Arguments(@"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", @"4869205468657265", @"afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6")]
	[Arguments(@"4a656665", @"7768617420646f2079612077616e7420666f72206e6f7468696e673f", @"af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649")]
	[Arguments(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", @"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", @"88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27")]
	[Arguments(@"0102030405060708090a0b0c0d0e0f10111213141516171819", @"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", @"3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb")]
	[Arguments(@"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", @"546573742057697468205472756e636174696f6e", @"3abf34c3503b2a23a46efc619baef897f4c8e42c934ce55ccbae9740fcbc1af4ca62269e2a37cd88ba926341efe4aeea")]
	[Arguments(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", @"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", @"4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952")]
	[Arguments(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", @"5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e", @"6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e")]
	public async Task TestSha384(string keyStr, string messageHex, string expected)
	{
		await VerifyVector<HmacAlgorithm<Sha384HashAlgorithm>>(keyStr, messageHex, expected);
	}

	[Test]
	[Arguments(@"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", @"4869205468657265", @"87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")]
	[Arguments(@"4a656665", @"7768617420646f2079612077616e7420666f72206e6f7468696e673f", @"164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737")]
	[Arguments(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", @"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", @"fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb")]
	[Arguments(@"0102030405060708090a0b0c0d0e0f10111213141516171819", @"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", @"b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd")]
	[Arguments(@"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", @"546573742057697468205472756e636174696f6e", @"415fad6271580a531d4179bc891d87a650188707922a4fbb36663a1eb16da008711c5b50ddd0fc235084eb9d3364a1454fb2ef67cd1d29fe6773068ea266e96b")]
	[Arguments(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", @"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", @"80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598")]
	[Arguments(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", @"5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e", @"e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58")]
	public async Task TestSha512(string keyStr, string messageHex, string expected)
	{
		await VerifyVector<HmacAlgorithm<Sha512HashAlgorithm>>(keyStr, messageHex, expected);
	}

	[Test]
	public Task Sha256LifecycleContract()
	{
		return VerifyLifecycleContract<HmacAlgorithm<Sha256HashAlgorithm>>();
	}

	[Test]
	public Task Sha256OwnershipContract()
	{
		return VerifyOwnershipContract<HmacAlgorithm<Sha256HashAlgorithm>>();
	}

	[Test]
	public async Task ShortDestinationsDoNotChangeStateOrOutput()
	{
		await VerifyShortDestinations<HmacAlgorithm<Sha256HashAlgorithm>>();
	}

	[Test]
	[Arguments(0)]
	[Arguments(97)]
	public async Task OneShotMacSupportsOverlappingInputsAndDestination(int destinationOffset)
	{
		await VerifyOneShotOverlap(destinationOffset);
	}

	[Test]
	public async Task FailedComputationDoesNotChangeOutputOrState()
	{
		byte[] key = CreateDeterministicSource(3);
		byte[] source = CreateDeterministicSource(3);
		byte[] expected = new byte[HmacAlgorithm<ThrowingHashAlgorithm>.MacLength];
		byte[] destination = new byte[HmacAlgorithm<ThrowingHashAlgorithm>.MacLength + 1];

		ThrowingHashAlgorithm.DisableFailure();
		_ = HmacAlgorithm<ThrowingHashAlgorithm>.Mac(key, source, expected);

		using HmacAlgorithm<ThrowingHashAlgorithm> macAlgorithm = HmacAlgorithm<ThrowingHashAlgorithm>.Create(key);
		macAlgorithm.Append(source);

		try
		{
			ThrowingHashAlgorithm.ThrowOnFinalize(2);
			PrepareDestination(destination);
			await Assert.That(() => HmacAlgorithm<ThrowingHashAlgorithm>.Mac(key, source, destination)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(destination).All(static value => value is DestinationSentinel);

			ThrowingHashAlgorithm.ThrowOnFinalize(2);
			PrepareDestination(destination);
			await Assert.That(() => macAlgorithm.GetCurrentMac(destination)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(destination).All(static value => value is DestinationSentinel);

			ThrowingHashAlgorithm.DisableFailure();
			PrepareDestination(destination);
			int written = macAlgorithm.GetCurrentMac(destination);
			await AssertOutput(destination, expected, written);

			ThrowingHashAlgorithm.ThrowOnFinalize(2);
			PrepareDestination(destination);
			await Assert.That(() => macAlgorithm.GetMacAndReset(destination)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(destination).All(static value => value is DestinationSentinel);

			ThrowingHashAlgorithm.DisableFailure();
			PrepareDestination(destination);
			written = macAlgorithm.GetMacAndReset(destination);
			await AssertOutput(destination, expected, written);
		}
		finally
		{
			ThrowingHashAlgorithm.DisableFailure();
		}
	}

	private static async Task VerifyOneShotOverlap(int destinationOffset)
	{
		const int keyOffset = 0;
		const int keyLength = 64;
		const int sourceOffset = 80;
		const int sourceLength = 97;
		int bufferLength = Math.Max(sourceOffset + sourceLength, destinationOffset + Sha256HashAlgorithm.HashLength);
		byte[] buffer = CreateDeterministicSource(bufferLength);
		byte[] expected = HMACSHA256.HashData
		(
			buffer.AsSpan().Slice(keyOffset, keyLength),
			buffer.AsSpan().Slice(sourceOffset, sourceLength)
		);

		int written = HmacAlgorithm<Sha256HashAlgorithm>.Mac
		(
			buffer.AsSpan().Slice(keyOffset, keyLength),
			buffer.AsSpan().Slice(sourceOffset, sourceLength),
			buffer.AsSpan().Slice(destinationOffset, Sha256HashAlgorithm.HashLength)
		);

		await Assert.That(written).IsEqualTo(Sha256HashAlgorithm.HashLength);
		await Assert.That(buffer.AsSpan().Slice(destinationOffset, written).ToArray()).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	private static async Task VerifyLifecycleContract<TMac>() where TMac : class, IMacAlgorithm<TMac>
	{
		byte[] key = CreateDeterministicSource(137);
		byte[] source = CreateDeterministicSource(173);
		byte[] expected = new byte[TMac.MacLength];
		byte[] prefixExpected = new byte[TMac.MacLength];
		byte[] destination = new byte[TMac.MacLength + 1];
		_ = TMac.Mac(key, source, expected);
		int split = source.Length / 2;
		_ = TMac.Mac(key, source.AsSpan().Slice(0, split), prefixExpected);

		using TMac macAlgorithm = TMac.Create(key);
		macAlgorithm.Append(source.AsSpan().Slice(0, split));
		PrepareDestination(destination);
		int written = macAlgorithm.GetCurrentMac(destination);
		await AssertOutput(destination, prefixExpected, written);

		macAlgorithm.Append(source.AsSpan().Slice(split));
		PrepareDestination(destination);
		written = macAlgorithm.GetCurrentMac(destination);
		await AssertOutput(destination, expected, written);
		PrepareDestination(destination);
		written = macAlgorithm.GetCurrentMac(destination);
		await AssertOutput(destination, expected, written);
		PrepareDestination(destination);
		written = macAlgorithm.GetMacAndReset(destination);
		await AssertOutput(destination, expected, written);

		macAlgorithm.Append(source);
		PrepareDestination(destination);
		written = macAlgorithm.GetMacAndReset(destination);
		await AssertOutput(destination, expected, written);

		macAlgorithm.Append(CreateDeterministicSource(17));
		macAlgorithm.Reset();
		macAlgorithm.Append(source);
		PrepareDestination(destination);
		written = macAlgorithm.GetMacAndReset(destination);
		await AssertOutput(destination, expected, written);
	}

	private static async Task VerifyOwnershipContract<TMac>() where TMac : class, IMacAlgorithm<TMac>
	{
		byte[] key = CreateDeterministicSource(37);
		byte[] source = CreateDeterministicSource(19);
		byte[] destination = new byte[TMac.MacLength];

		using TMac owner = TMac.Create(key);
		TMac alias = owner;
		alias.Dispose();
		alias.Dispose();

		await Assert.That(() => owner.Append(source)).ThrowsExactly<ObjectDisposedException>();
		await Assert.That(owner.Reset).ThrowsExactly<ObjectDisposedException>();
		await Assert.That(() => owner.GetCurrentMac(destination)).ThrowsExactly<ObjectDisposedException>();
		await Assert.That(() => owner.GetMacAndReset(destination)).ThrowsExactly<ObjectDisposedException>();
	}

	private static async Task VerifyShortDestinations<TMac>() where TMac : class, IMacAlgorithm<TMac>
	{
		byte[] key = CreateDeterministicSource(137);
		byte[] source = CreateDeterministicSource(73);
		byte[] expected = new byte[TMac.MacLength];
		TMac.Mac(key, source, expected);
		byte[] shortDestination = new byte[TMac.MacLength - 1];
		byte[] destination = new byte[TMac.MacLength + 1];
		using TMac macAlgorithm = TMac.Create(key);
		macAlgorithm.Append(source);

		PrepareDestination(shortDestination);
		await Assert.That(() => macAlgorithm.GetCurrentMac(shortDestination)).Throws<ArgumentException>();
		await Assert.That(shortDestination).All(static value => value is DestinationSentinel);
		PrepareDestination(destination);
		int written = macAlgorithm.GetCurrentMac(destination);
		await AssertOutput(destination, expected, written);

		PrepareDestination(shortDestination);
		await Assert.That(() => macAlgorithm.GetMacAndReset(shortDestination)).Throws<ArgumentException>();
		await Assert.That(shortDestination).All(static value => value is DestinationSentinel);
		PrepareDestination(destination);
		written = macAlgorithm.GetMacAndReset(destination);
		await AssertOutput(destination, expected, written);

		byte[] keyCopy = (byte[])key.Clone();
		byte[] sourceCopy = (byte[])source.Clone();
		PrepareDestination(shortDestination);
		await Assert.That(() => TMac.Mac(key, source, shortDestination)).Throws<ArgumentException>();
		await Assert.That(shortDestination).All(static value => value is DestinationSentinel);
		await Assert.That(key).IsEquivalentTo(keyCopy, CollectionOrdering.Matching);
		await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);
	}

	private struct ThrowingHashAlgorithm : IHmacHashCore<ThrowingHashAlgorithm>
	{
		private static int _finalizationCount;
		private static int _throwOnFinalization;

		private uint _sum;

		public static void ThrowOnFinalize(int finalizationNumber)
		{
			Interlocked.Exchange(ref _finalizationCount, 0);
			Interlocked.Exchange(ref _throwOnFinalization, finalizationNumber);
		}

		public static void DisableFailure()
		{
			Interlocked.Exchange(ref _throwOnFinalization, 0);
			Interlocked.Exchange(ref _finalizationCount, 0);
		}

		public static int HashLength => sizeof(uint);

		public static int HmacBlockSize => 8;

		static ThrowingHashAlgorithm IHashCore<ThrowingHashAlgorithm>.Create()
		{
			return default;
		}

		void IIncrementalHashCore.Append(ReadOnlySpan<byte> source)
		{
			foreach (byte value in source)
			{
				_sum += value;
			}
		}

		readonly void IIncrementalHashCore.Finalize(Span<byte> destination)
		{
			if (destination.Length < sizeof(uint))
			{
				throw new ArgumentException(null, nameof(destination));
			}

			BinaryPrimitives.WriteUInt32LittleEndian(destination, _sum);

			if (Interlocked.Increment(ref _finalizationCount) == Volatile.Read(ref _throwOnFinalization))
			{
				throw new InvalidOperationException();
			}
		}
	}
}
