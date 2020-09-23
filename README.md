<div align="center">

## clsTripleDES\.vb


</div>

### Description

Encryption / Decryption of String
 
### More Info
 
Triple DES algorithm used in combination with conversion to base64 string within Encrypted / Decrypted properties for easy storage in e.g. database. Uses MemoryStream as opposed to FileStream. Key() should be stored in seperate binary.


<span>             |<span>
---                |---
**Submitted On**   |
**By**             |[RobJames](https://github.com/Planet-Source-Code/PSCIndex/blob/master/ByAuthor/robjames.md)
**Level**          |Intermediate
**User Rating**    |3.7 (11 globes from 3 users)
**Compatibility**  |VB\.NET
**Category**       |[Security](https://github.com/Planet-Source-Code/PSCIndex/blob/master/ByCategory/security__10-14.md)
**World**          |[\.Net \(C\#, VB\.net\)](https://github.com/Planet-Source-Code/PSCIndex/blob/master/ByWorld/net-c-vb-net.md)
**Archive File**   |[](https://github.com/Planet-Source-Code/robjames-clstripledes-vb__10-1564/archive/master.zip)

### API Declarations

Based on Wrox article http://www.devarticles.com/art/1/249/6.


### Source Code

```
Imports System
Imports System.IO
Imports System.Text
Imports System.Security.Cryptography
Imports System.Xml
Public Class clsTES
  Private _CreditCardNumber As String
  Private _EncCreditCardNumber As String
  Public Property CreditCardNumber() As String
    Get
      Return _CreditCardNumber
    End Get
    Set(ByVal Value As String)
      'exit if no value
      If Value = String.Empty Then Exit Property
      _CreditCardNumber = Value
      'encrypt class ref. set
      Dim objTES As New clsTES()
      'encrypt ccard string
      Dim baEnc As Byte() = objTES.Encrypt(_CreditCardNumber)
      'get base64 string from byte array
      Dim s64 As String = System.Convert.ToBase64String(baEnc)
      'set class string enc.
      _EncCreditCardNumber = s64
    End Set
  End Property
  Public Property EncryptedCreditCardNumber() As String
    Get
      Return _EncCreditCardNumber
    End Get
    Set(ByVal Value As String)
      'exit if no value
      If Value = String.Empty Then Exit Property
      If _CreditCardNumber = String.Empty Then Exit Property
      _EncCreditCardNumber = Value
      'decrypt class ref. set
      Dim objTES As New clsTES()
      'get byte array from base64 string i.e. from db stored as base64
      Dim baDec As Byte() = System.Convert.FromBase64String(_CreditCardNumber)
      'decrypt ccard string
      Dim sDec As String = objTES.Decrypt(baDec)
      'set string decrypted
      _CreditCardNumber = sDec
    End Set
  End Property
  'keys
  Private key() As Byte = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
  Private iv() As Byte = {65, 110, 68, 26, 69, 178, 200, 219}
  Public Function Encrypt(ByVal plainText As String) As Byte()
    ' Declare a UTF8Encoding object so we may use the GetByte
    ' method to transform the plainText into a Byte array.
    Dim utf8encoder As UTF8Encoding = New UTF8Encoding()
    Dim inputInBytes() As Byte = utf8encoder.GetBytes(plainText)
    ' Create a new TripleDES service provider
    Dim tdesProvider As TripleDESCryptoServiceProvider = New TripleDESCryptoServiceProvider()
    ' The ICryptTransform interface uses the TripleDES
    ' crypt provider along with encryption key and init vector
    ' information
    Dim cryptoTransform As ICryptoTransform = tdesProvider.CreateEncryptor(Me.key, Me.iv)
    ' All cryptographic functions need a stream to output the
    ' encrypted information. Here we declare a memory stream
    ' for this purpose.
    Dim encryptedStream As MemoryStream = New MemoryStream()
    Dim cryptStream As CryptoStream = New CryptoStream(encryptedStream, _
                    cryptoTransform, CryptoStreamMode.Write)
    ' Write the encrypted information to the stream. Flush the information
    ' when done to ensure everything is out of the buffer.
    cryptStream.Write(inputInBytes, 0, inputInBytes.Length)
    cryptStream.FlushFinalBlock()
    encryptedStream.Position = 0
    ' Read the stream back into a Byte array and return it to the calling
    ' method.
    Dim result(encryptedStream.Length - 1) As Byte
    encryptedStream.Read(result, 0, encryptedStream.Length)
    cryptStream.Close()
    'test section
    'Convert to / fro the memory stream to a base64 string
    'compare decText to result
    Dim encText As String = Convert.ToBase64String(encryptedStream.ToArray())
    Dim decText As Byte() = Convert.FromBase64String(encText)
    Dim sDec As String = Decrypt(decText)
    Return result
  End Function
  Public Function Decrypt(ByVal inputInBytes() As Byte) As String
    ' UTFEncoding is used to transform the decrypted Byte Array
    ' information back into a string.
    Dim utf8encoder As UTF8Encoding = New UTF8Encoding()
    Dim tdesProvider As TripleDESCryptoServiceProvider = New _
    TripleDESCryptoServiceProvider()
    ' As before we must provide the encryption/decryption key along with
    ' the init vector.
    Dim cryptoTransform As ICryptoTransform = _
    tdesProvider.CreateDecryptor(Me.key, Me.iv)
    ' Provide a memory stream to decrypt information into
    Dim decryptedStream As MemoryStream = New MemoryStream()
    Dim cryptStream As CryptoStream = New CryptoStream(decryptedStream, _
    cryptoTransform, CryptoStreamMode.Write)
    cryptStream.Write(inputInBytes, 0, inputInBytes.Length)
    cryptStream.FlushFinalBlock()
    decryptedStream.Position = 0
    ' Read the memory stream and convert it back into a string
    Dim result(decryptedStream.Length - 1) As Byte
    decryptedStream.Read(result, 0, decryptedStream.Length)
    cryptStream.Close()
    Dim myutf As UTF8Encoding = New UTF8Encoding()
    Return myutf.GetString(result)
  End Function
End Class
```

