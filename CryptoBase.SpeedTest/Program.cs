using CryptoBase;
using CryptoBase.SpeedTest;
using System;
using System.Diagnostics;

Console.WriteLine("Start CryptoBase.SpeedTest...");
#if DEBUG
Console.WriteLine("On Debug mode");
#endif
if (Debugger.IsAttached)
{
	Console.WriteLine("Debugger attached!");
}

Console.WriteLine($@"OS Version: {Environment.OSVersion}");
Console.WriteLine($@".NET Version: {Environment.Version}");
Console.WriteLine($@"CPU Vendor: {CpuIdUtils.GetVendor()}");
Console.WriteLine($@"CPU Brand: {CpuIdUtils.GetBrand()}");
Console.WriteLine($@"Intel SHA extensions: {CpuIdUtils.IsSupportX86ShaEx()}");

var key32 = CryptoTest.Key.Slice(0, 32).ToArray();
var key16 = CryptoTest.Key.Slice(0, 16).ToArray();
var iv16 = CryptoTest.IV.Slice(0, 16).ToArray();
var iv24 = CryptoTest.IV.Slice(0, 24).ToArray();

Console.Write(@"Testing Aes-128-Ctr: ");
CryptoTest.Test(StreamCryptoCreate.AesCtr(key16, iv16));
Console.Write(@"Testing Sm4-Ctr: ");
CryptoTest.Test(StreamCryptoCreate.Sm4Ctr(key16, iv16));
Console.Write(@"Testing Aes-128-Cfb: ");
CryptoTest.Test(StreamCryptoCreate.AesCfb(true, key16, iv16));
Console.Write(@"Testing Sm4-Cfb: ");
CryptoTest.Test(StreamCryptoCreate.Sm4Cfb(true, key16, iv16));
Console.Write(@"Testing RC4: ");
CryptoTest.Test(StreamCryptoCreate.Rc4(key16));
Console.Write(@"Testing ChaCha20: ");
CryptoTest.Test(StreamCryptoCreate.ChaCha20(key32, iv16));
Console.Write(@"Testing ChaCha20Original: ");
CryptoTest.Test(StreamCryptoCreate.ChaCha20Original(key32, iv16));
Console.Write(@"Testing XChaCha20: ");
CryptoTest.Test(StreamCryptoCreate.XChaCha20(key32, iv24));
Console.Write(@"Testing Salsa20: ");
CryptoTest.Test(StreamCryptoCreate.Salsa20(key32, iv16));
Console.Write(@"Testing XSalsa20: ");
CryptoTest.Test(StreamCryptoCreate.XSalsa20(key32, iv24));

Console.Write(@"Testing AES-128-GCM: ");
CryptoTest.Test(AEADCryptoCreate.AesGcm(key16));
Console.Write(@"Testing SM4-GCM: ");
CryptoTest.Test(AEADCryptoCreate.Sm4Gcm(key16));
Console.Write(@"Testing ChaCha20Poly1305: ");
CryptoTest.Test(AEADCryptoCreate.ChaCha20Poly1305(key32));
Console.Write(@"Testing XChaCha20Poly1305: ");
CryptoTest.Test(AEADCryptoCreate.XChaCha20Poly1305(key32), 24);
