open System

type String512 = String512 of string
module String512 =
    let create (s : string) =
        if s <> null && s.Length <= 512
        then Some (String512 s)
        else None
    let apply f (String512 s) = f s
    let value s = apply id s

type PlaintextToken = PlaintextToken of String512
type ProtectedToken = ProtectedToken of String512

type EdgeCastKey = EdgeCastKey of Org.BouncyCastle.Crypto.Parameters.KeyParameter
module EdgeCastKey =
    let create (s : Org.BouncyCastle.Crypto.Parameters.KeyParameter) =
        EdgeCastKey s
    let apply f (EdgeCastKey s) = f s
    let value s = apply id s

module internal EdgecastCrypto =
    open System.IO 
    open Org.BouncyCastle.Crypto
    open Org.BouncyCastle.Crypto.Engines
    open Org.BouncyCastle.Crypto.Modes
    open Org.BouncyCastle.Security
    open Org.BouncyCastle.Crypto.Parameters
    
    module internal Helpers =
        open System.Text
        open System.Security.Cryptography
    
        let sha256(x : byte[]) = x |> (SHA256.Create()).ComputeHash
        
        let trimEnd (a: char) (str: string) = str.TrimEnd(a)

        let replaceStr (a: string) (b: string) (str: string) = str.Replace(a, b)
        let replaceChar (a: char) (b: char) (str: string) = str.Replace(a, b)

        let toUTF8 (s : string) = s |> Encoding.UTF8.GetBytes
        let fromUTF8 (x:  byte[]) = x |> Encoding.UTF8.GetString
        
        let private removeBase64Padding = trimEnd '=' 

        let private restoreBase64Padding (s : string) = 
            match (s.Length % 4) with
            | 0 -> s
            | 3 -> s + "="
            | 2 -> s + "=="
            | _ -> failwith "Illegal base64url string"
        
        let private properBase64toSafeUrl s = 
            s
            |> replaceChar '+' '-'
            |> replaceChar '/' '_'

        let private safeUrlToProperBase64 s = 
            s
            |> replaceChar '_' '/'
            |> replaceChar '-' '+'
    
        let toSafeBase64 (s: byte[]) = 
            s
            |> Convert.ToBase64String
            |> removeBase64Padding
            |> properBase64toSafeUrl
        
        let fromSafeBase64 (s: string) =
            s
            |> safeUrlToProperBase64
            |> restoreBase64Padding
            |> Convert.FromBase64String

    open Helpers
    
    let createKey (value : string) =
        value
        |> toUTF8
        |> sha256
        |> (fun d -> EdgeCastKey (new KeyParameter(d)))

    let createPlaintext str =
        str 
        |> String512.create
        |> function
            | None -> None
            | Some(x) -> Some(PlaintextToken(x))

    let createProtected str =
        str 
        |> String512.create
        |> function
            | None -> None
            | Some(x) -> Some(ProtectedToken(x))

    let private NonceByteSize = 12

    let private secureRandom = new SecureRandom()

    let private createIV =
        let iv = Array.zeroCreate<byte> NonceByteSize
        secureRandom.NextBytes(iv)
        iv
    
    let private createCipher key iv forEncryption =
        let cipher = new GcmBlockCipher(new AesEngine())
        let parameters = new ParametersWithIV (key, iv)
        cipher.Init(forEncryption = forEncryption, parameters = parameters)
        cipher

    let private encrypt_impl(key : EdgeCastKey) (plaintext: byte[]) =
        let iv = createIV
        let cipher = createCipher (EdgeCastKey.value key) iv true
        let cipherText = Array.zeroCreate<byte>(cipher.GetOutputSize(plaintext.Length))
        let len = cipher.ProcessBytes(input = plaintext, inOff = 0, len = plaintext.Length, output = cipherText, outOff = 0)
        cipher.DoFinal(cipherText, len) |> ignore
        use memoryStream = new MemoryStream()
        using (new BinaryWriter(memoryStream)) (fun w -> 
            w.Write(iv)
            w.Write(cipherText)
        )
        memoryStream.ToArray()

    let private decrypt_impl(key : EdgeCastKey) (ciphertext: byte[]) =
        try        
            use cipherStream = new MemoryStream (ciphertext)
            use cipherReader = new BinaryReader (cipherStream)
            let iv = cipherReader.ReadBytes(NonceByteSize)
            let cipher = createCipher (EdgeCastKey.value key) iv false
            let cipherText = cipherReader.ReadBytes(ciphertext.Length - NonceByteSize)
            let plainText = Array.zeroCreate<byte>(cipher.GetOutputSize(cipherText.Length))
            let len = cipher.ProcessBytes(input = cipherText, inOff = 0, len = cipherText.Length, output = plainText, outOff = 0)
            cipher.DoFinal(plainText, len) |> ignore
            plainText
        with 
        | :? InvalidCipherTextException -> Array.empty

    let encrypt key (token : PlaintextToken option) =
        token
        |> function
        | None -> None
        | Some(PlaintextToken(plaintext)) -> 
            plaintext
            |> String512.value
            |> replaceStr "ec_secure=1" ""
            |> replaceStr "&&" "&"
            |> toUTF8
            |> encrypt_impl key
            |> toSafeBase64
            |> createProtected

    let decrypt key (token : ProtectedToken option) =
        token
        |> function
        | None -> None
        | Some(ProtectedToken(ciphertext)) -> 
            ciphertext
            |> String512.value
            |> fromSafeBase64
            |> decrypt_impl key
            |> fromUTF8
            |> createPlaintext 
    
open EdgecastCrypto

[<EntryPoint>]
let main argv =
    let inspect msg a =
        printfn "%s: %A" msg a
        a

    let kv = "primary202109099dc4cf480b17a94f5eef938bdb08c18535bcc777cc0420c29133d0134d635aa78a1e28f6b883619ed5f920bd3cd79bfe10c42b5d96b7eeb84571ceee4cb51d89"
    let key = EdgecastCrypto.createKey kv
    
    "ec_expire=1522944645&ec_clientip=0.0.0.0&ec_country_allow=US&ec_country_deny=NA&ec_ref_allow=1234&ec_ref_deny=456"
    |> EdgecastCrypto.createPlaintext
    |> inspect "plaintext"
    |> EdgecastCrypto.encrypt key
    |> inspect "encrypted"
    |> EdgecastCrypto.decrypt key
    |> inspect "decrypted"
    |> function
        | None -> 
            "Something went wrong"
        | Some(PlaintextToken(plaintext)) -> 
            sprintf "Decoded: %s" (String512.value plaintext)
    |> printf "%s"

    0