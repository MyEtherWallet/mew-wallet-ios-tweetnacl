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
  public static let PublicKeyLength = 32
  public static let SecretKeyLength = 32
  public static let BeforeNMLength = 32
  
  struct SecretBox {
    public static let keyLength = 32
    public static let nonceLength = 24
    public static let zeroLength = 32
    public static let boxZeroLength = 16
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

// Based on https://github.com/dchest/tweetnacl-js
public class TweetNacl {
  
  // MARK: - Keys

  /// Creates key pair on curve25519 as specified in EIP1024. Pass nil to create a new key pair or an Ethereum private key
  /// to create a key pair linked to an Ethereum key pair.
  /// Based on nacl.box.keyPair.fromSecretKey and nacl.box.keyPair
  /// - Parameter fromSecretKey: Ethereum private key
  /// - Returns: curve25519 key pair
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
    
  /// Pre-calculate shared secret key
  /// Based on nacl.box.before
  /// - Parameters:
  ///   - publicKey: public key
  ///   - secretKey: private key
  /// - Returns: shared key
  internal static func before(publicKey: Data, secretKey: Data) throws -> Data {
    guard publicKey.count == Constants.PublicKeyLength else { throw TweetNaclError.invalidPublicKey }
    guard secretKey.count == Constants.SecretKeyLength else { throw TweetNaclError.invalidSecretKey }
      
    var publicKey = [UInt8](publicKey)
    var secretKey = [UInt8](secretKey)
    var k = [UInt8](repeating: 0, count: Constants.BeforeNMLength)
      
    let result = crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(&k, &publicKey, &secretKey)
    guard result == 0 else { throw TweetNaclError.tweetNacl("[TweetNacl.before] Internal error code: \(result)") }
      
    return Data(k)
  }
    
  // MARK: - Decryption
    
  /// Decrypts encrypted message
  /// Based on nacl.box.open
  /// - Parameters:
  ///   - message: secret box
  ///   - nonce: unique nonce
  ///   - publicKey: public curve25519 key provided by sender
  ///   - secretKey: receiver's private curve25519 key to decrypt message
  /// - Returns: clear text
  public static func open(message: Data, nonce: Data, publicKey: Data, secretKey: Data) throws -> Data {
    let k = try before(publicKey: publicKey, secretKey: secretKey)
    return try open(box: message, nonce: nonce, key: k)
  }
  
  /// Decrypts encrypted message
  /// Based on nacl.secretbox.open
  /// - Parameters:
  ///   - box: secret box
  ///   - nonce: unique nonce
  ///   - key: private key
  /// - Returns: clear text of message
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
    
  // MARK: - Encryption
    
  /// Encrypts message, creates secretbox
  /// Based on nacl.box
  /// - Parameters:
  ///   - message: Clear text message
  ///   - theirPublicKey: Recipient's public key
  ///   - mySecretKey: Sender's private key
  ///   - nonce: nonce (pass nil for random nonce)
  /// - Returns: secret box
  public static func box(message: Data, recipientPublicKey: Data, senderSecretKey: Data, nonce: Data? = nil) throws -> Data {
    let k = try before(publicKey: recipientPublicKey, secretKey: senderSecretKey)
    return try secretbox(message: message, nonce: nonce ?? randomNonce(), key: k)
  }
    
  /// Encrypts message, creates secretbox
  /// Based on nacl.secretbox
  /// - Parameters:
  ///   - message: Clear text message
  ///   - nonce: Unique nonce
  ///   - key: Shared secret key
  /// - Returns: secret box
  private static func secretbox(message: Data, nonce: Data, key: Data) throws -> Data {
    guard key.count == Constants.SecretBox.keyLength else { throw TweetNaclError.invalidKey }
    guard nonce.count == Constants.SecretBox.nonceLength else { throw TweetNaclError.invalidNonce }
      
    var mData = Data(count: Constants.SecretBox.zeroLength + message.count)
    mData.replaceSubrange(Constants.SecretBox.zeroLength ..< mData.count, with: message)
    var m = [UInt8](mData)
    var c = [UInt8](repeating: 0, count: m.count)
    var nonce = [UInt8](nonce)
    var key = [UInt8](key)
      
    let result = crypto_secretbox_xsalsa20poly1305_tweet(&c, &m, UInt64(m.count), &nonce, &key)
    guard result == 0 else { throw TweetNaclError.tweetNacl("[TweetNacl.secretbox] Internal error code: \(result)") }
    
    return Data(c[Constants.SecretBox.boxZeroLength..<c.count])
  }
    
  private static func randomNonce() throws -> Data {
    var nonce = [UInt8](repeating: 0, count: Constants.SecretBox.nonceLength)
    let status = SecRandomCopyBytes(kSecRandomDefault, Constants.SecretBox.nonceLength, &nonce)
    guard status == errSecSuccess else {
      throw TweetNaclError.tweetNacl("Secure random bytes error")
    }
    return Data(nonce)
  }
}

// Source: https://github.com/dchest/tweetnacl-js
// https://www.tabnine.com/code/javascript/modules/tweetnacl

/*
 
 
 // box
 
 nacl.box = function(msg, nonce, publicKey, secretKey) {
   var k = nacl.box.before(publicKey, secretKey);
   return nacl.secretbox(msg, nonce, k);
 };

 nacl.box.before = function(publicKey, secretKey) {
   checkArrayTypes(publicKey, secretKey);
   checkBoxLengths(publicKey, secretKey);
   var k = new Uint8Array(crypto_box_BEFORENMBYTES);
   crypto_box_beforenm(k, publicKey, secretKey);
   return k;
 };

 nacl.box.after = nacl.secretbox;

 nacl.box.open = function(msg, nonce, publicKey, secretKey) {
   var k = nacl.box.before(publicKey, secretKey);
   return nacl.secretbox.open(msg, nonce, k);
 };

 nacl.box.open.after = nacl.secretbox.open;

 nacl.box.keyPair = function() {
   var pk = new Uint8Array(crypto_box_PUBLICKEYBYTES);
   var sk = new Uint8Array(crypto_box_SECRETKEYBYTES);
   crypto_box_keypair(pk, sk);
   return {publicKey: pk, secretKey: sk};
 };

 nacl.box.keyPair.fromSecretKey = function(secretKey) {
   checkArrayTypes(secretKey);
   if (secretKey.length !== crypto_box_SECRETKEYBYTES)
     throw new Error('bad secret key size');
   var pk = new Uint8Array(crypto_box_PUBLICKEYBYTES);
   crypto_scalarmult_base(pk, secretKey);
   return {publicKey: pk, secretKey: new Uint8Array(secretKey)};
 };
 
 
 // Secretbox
 nacl.secretbox = function(msg, nonce, key) {
   checkArrayTypes(msg, nonce, key);
   checkLengths(key, nonce);
   var m = new Uint8Array(crypto_secretbox_ZEROBYTES + msg.length);
   var c = new Uint8Array(m.length);
   for (var i = 0; i < msg.length; i++) m[i+crypto_secretbox_ZEROBYTES] = msg[i];
   crypto_secretbox(c, m, m.length, nonce, key);
   return c.subarray(crypto_secretbox_BOXZEROBYTES);
 };

 nacl.secretbox.open = function(box, nonce, key) {
   checkArrayTypes(box, nonce, key);
   checkLengths(key, nonce);
   var c = new Uint8Array(crypto_secretbox_BOXZEROBYTES + box.length);
   var m = new Uint8Array(c.length);
   for (var i = 0; i < box.length; i++) c[i+crypto_secretbox_BOXZEROBYTES] = box[i];
   if (c.length < 32) return null;
   if (crypto_secretbox_open(m, c, c.length, nonce, key) !== 0) return null;
   return m.subarray(crypto_secretbox_ZEROBYTES);
 };

 
 
 */
