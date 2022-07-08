//
//  TweetNacl.swift
//  MEWwalletTweetNacl
//
//  Created by Mikhail Nikanorov on 6/15/21.
//  Copyright © 2021 MyEtherWallet Inc. All rights reserved.
//

import Foundation
import MEWwalletCTweetNacl

struct Constants {
  static let PublicKeyLength = 32
  static let SecretKeyLength = 32
  static let BeforeNMLength = 32
  
  struct SecretBox {
    static let keyLength = 32
    static let nonceLength = 24
    static let zeroLength = 32
    static let boxZeroLength = 16
  }
}

public enum TweetNaclError: LocalizedError {
  case invalidSecretKey
  case invalidPublicKey
  case invalidKey
  case invalidNonce
  case tweetNacl(String)
  
  public var errorDescription: String? {
    switch self {
    case .invalidSecretKey: return "Wrong SecretKey length"
    case .invalidPublicKey: return "Wrong PublicKey length"
    case .invalidKey:       return "Wrong Key length"
    case .invalidNonce:     return "Wrong Nonce length"
    case .tweetNacl:        return "Internal TweetNacl error"
    }
  }
  
  public var failureReason: String? {
    switch self {
    case .invalidSecretKey:       return "SecretKey length should be \(Constants.SecretKeyLength) bytes length"
    case .invalidPublicKey:       return "PublicKey should be \(Constants.PublicKeyLength) bytes length"
    case .invalidKey:             return "Key should be \(Constants.SecretBox.keyLength) bytes length"
    case .invalidNonce:           return "Nonce should be \(Constants.SecretBox.nonceLength) bytes length"
    case let .tweetNacl(message): return "TweetNacl error: \(message)"
    }
  }
  
  public var recoverySuggestion: String? {
    switch self {
    case .invalidSecretKey: return "Check SecretKey length"
    case .invalidPublicKey: return "Check PublicKey length"
    case .invalidKey:       return "Check Key length"
    case .invalidNonce:     return "Check Nonce length"
    case .tweetNacl:        return "Internal TweetNacl error"
    }
  }
  
  public var localizedDescription: String {
    return "\(self.errorDescription ?? ""). Recovery: \(self.recoverySuggestion ?? "")"
  }
}

public class TweetNacl {
  public static func keyPair(fromSecretKey: Data? = nil) throws -> (publicKey: Data, secretKey: Data) {
    var sk: [UInt8]
    if let fromSecretKey = fromSecretKey {
      guard fromSecretKey.count == Constants.SecretKeyLength else { throw TweetNaclError.invalidSecretKey }
      sk = [UInt8](fromSecretKey)
    } else {
        sk = [UInt8](repeating: 0, count: Constants.SecretKeyLength)
        let status = SecRandomCopyBytes(kSecRandomDefault, Constants.SecretKeyLength, &sk)
        guard status == errSecSuccess else {
            throw TweetNaclError.tweetNacl("Secure random bytes error")
        }
    }
          
    var pk = [UInt8](repeating: 0, count: Constants.PublicKeyLength)
    
    let result = crypto_scalarmult_curve25519_tweet_base(&pk, &sk)
    
    guard result == 0 else { throw TweetNaclError.tweetNacl("[TweetNacl.keyPair] Internal error code: \(result)") }
    
    return (Data(pk), Data(sk))
  }        
  
  public static func open(message: Data, nonce: Data, publicKey: Data, secretKey: Data) throws -> Data {
    let k = try before(publicKey: publicKey, secretKey: secretKey)
    return try open(box: message, nonce: nonce, key: k)
  }
  
  public static func before(publicKey: Data, secretKey: Data) throws -> Data {
    guard publicKey.count == Constants.PublicKeyLength else { throw TweetNaclError.invalidPublicKey }
    guard secretKey.count == Constants.SecretKeyLength else { throw TweetNaclError.invalidSecretKey }
    
    var publicKey = [UInt8](publicKey)
    var secretKey = [UInt8](secretKey)
    
    var k = [UInt8](repeating: 0, count: Constants.BeforeNMLength)
    
    let result = crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(&k, &publicKey, &secretKey)
    guard result == 0 else { throw TweetNaclError.tweetNacl("[TweetNacl.before] Internal error code: \(result)") }
    
    return Data(k)
  }
  
  public static func open(box: Data, nonce: Data, key: Data) throws -> Data {
    guard key.count == Constants.SecretBox.keyLength else { throw TweetNaclError.invalidKey }
    guard nonce.count == Constants.SecretBox.nonceLength else { throw TweetNaclError.invalidNonce }
    
    var cData = Data(count: Constants.SecretBox.boxZeroLength + box.count)
    cData.replaceSubrange(Constants.SecretBox.boxZeroLength..<cData.count, with: box)
    
    var m = [UInt8](repeating: 0, count: cData.count)
    var c = [UInt8](cData)
    var nonce = [UInt8](nonce)
    var key = [UInt8](key)
    
    let result = crypto_secretbox_xsalsa20poly1305_tweet_open(&m, &c, UInt64(cData.count), &nonce, &key)
    guard result == 0 else { throw TweetNaclError.tweetNacl("[TweetNacl.open] Internal error code: \(result)") }
    
    return Data(m[Constants.SecretBox.zeroLength..<c.count])
  }
    
  public static func box(message: String, nonce: Data, theirPublicKey: Data, mySecretKey: Data) throws -> Data {
    let k = try before(publicKey: theirPublicKey, secretKey: mySecretKey)
    guard let data = message.data(using: .utf8) else { throw TweetNaclError.tweetNacl("Invalid message")}
    return try secretbox(message: data, nonce: nonce, key: k)
  }

  private static func secretbox(message: Data, nonce: Data, key: Data) throws -> Data {
    guard key.count == Constants.SecretBox.keyLength else { throw TweetNaclError.invalidKey }
    guard nonce.count == Constants.SecretBox.nonceLength else { throw TweetNaclError.invalidNonce }
      
    var mData = Data(count: message.count + Constants.SecretBox.boxZeroLength)
    mData.replaceSubrange(Constants.SecretBox.boxZeroLength..<mData.count, with: message)
    let m = [UInt8](mData)
    var c = [UInt8](repeating: 0, count: message.count)
    var nonce = [UInt8](nonce)
    var key = [UInt8](key)
      
    let result = crypto_secretbox_xsalsa20poly1305_tweet(&c, m, UInt64(m.count), &nonce, &key)
    guard result == 0 else { throw TweetNaclError.tweetNacl("[TweetNacl.secretbox] Internal error code: \(result)") }
    
    return Data(c[0..<Constants.SecretBox.zeroLength])
    }
}
