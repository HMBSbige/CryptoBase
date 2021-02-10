# CryptoBase

C# 密码库抽象接口与默认实现

## 目标
### 消息摘要算法
* MD5
* SHA1
* SM3

### 对称加密
#### 流加密
* ChaCha20
    * Original
    * IETF 7539
* RC4
* Salsa20
* XChaCha20
* XSalsa20

#### 块加密
* AES
* SM4

##### 加密模式
* CBC
* CFB
* CTR

#### 认证加密
* ChaCha20Poly1305
* AES-GCM
* SM4-GCM
* XChaCha20Poly1305
