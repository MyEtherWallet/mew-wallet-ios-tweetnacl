import XCTest
@testable import MEWwalletTweetNacl

final class MEWwalletTweetNaclTests: XCTestCase {
  let nonce = "1dvWO7uOnBnO7iNDJ9kO9pTasLuKNlej"
  let ephemPublicKey = "FBH1/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ="
  let cipherText = "f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy"
  let privateKey = Data([0x7e, 0x53, 0x74, 0xec, 0x2e, 0xf0, 0xd9, 0x17, 0x61, 0xa6, 0xe7, 0x2f, 0xdf, 0x8f, 0x6a, 0xc6, 0x65, 0x51, 0x9b, 0xfd, 0xf6, 0xda, 0x0a, 0x23, 0x29, 0xcf, 0x0d, 0x80, 0x45, 0x14, 0xb8, 0x16])
  
  func testDecode() {
    do {
      let sk = try TweetNacl.keyPair(fromSecretKey: privateKey).secretKey
      guard let nonceData = Data(base64Encoded: self.nonce),
            let cipherTextData = Data(base64Encoded: self.cipherText),
            let ephemPublicKeyData = Data(base64Encoded: self.ephemPublicKey) else {
        XCTFail("Can't get data")
        return
      }
      let decrypted = try TweetNacl.open(
        message: cipherTextData,
        nonce: nonceData,
        publicKey: ephemPublicKeyData,
        secretKey: sk)
      
      guard let message = String(data: decrypted, encoding: .utf8) else {
        XCTFail("Can't create a string")
        return
      }
      XCTAssertEqual(message, "My name is Satoshi Buterin")
      debugPrint(message)
    } catch {
      XCTFail((error as? LocalizedError)?.failureReason ?? error.localizedDescription)
    }
  }
    
  /*
    Tope's example:
    getEncryptionPublicKey(7e5374ec2ef0d91761a6e72fdf8f6ac665519bfdf6da0a2329cf0d804514b816) should return a public encryption key of the form "C5YMNdqE4kLgxQhJO1MfuQcHP5hjVSXzamzd/TxlR0U="
    
    web3.eth.encrypt("C5YMNdqE4kLgxQhJO1MfuQcHP5hjVSXzamzd/TxlR0U=", 'x25519-xsalsa20-poly1305-v1', {data: 'My name is Satoshi Buterin'}) should return a blob of the form { version: 'x25519-xsalsa20-poly1305', nonce: '1dvWO7uOnBnO7iNDJ9kO9pTasLuKNlej', ephemPublicKey: 'FBH1/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ=', ciphertext: 'f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy' }
    
    web3.eth.decrypt('7e5374ec2ef0d91761a6e72fdf8f6ac665519bfdf6da0a2329cf0d804514b816', { version: 'x25519-xsalsa20-poly1305', nonce: '1dvWO7uOnBnO7iNDJ9kO9pTasLuKNlej', ephemPublicKey: 'FBH1/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ=', ciphertext: 'f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy' }) should return plain text/file of the form { data:'My name is Satoshi Buterin' }
     */
    
  func testEncode() throws {
    let receiverKeys = try TweetNacl.keyPair(fromSecretKey: privateKey)
    let ephemPublicKeyData = Data(base64Encoded: self.ephemPublicKey)!
    let message = "My name is Satoshi Buterin".data(using: .utf8)!
    let nonceData = Data(base64Encoded: self.nonce)!
    
    XCTAssertEqual(String(data: receiverKeys.publicKey.base64EncodedData(), encoding: .utf8), "C5YMNdqE4kLgxQhJO1MfuQcHP5hjVSXzamzd/TxlR0U=")
    XCTAssertEqual(String(data: ephemPublicKeyData.base64EncodedData(), encoding: .utf8), "FBH1/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ=")
      
    // encrypt
      // issue is that web3.eth.encrypt is called with public key, while we call with secret eph key
    let secretbox = try TweetNacl.box(message: message, recipientPublicKey: receiverKeys.publicKey, senderSecretKey: ephemPublicKeyData, nonce: nonceData)
    let secretboxString = String(data: secretbox.base64EncodedData(), encoding: .utf8)!
    let expectedCiphertext = "f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy"
    XCTAssertEqual(secretboxString.count, expectedCiphertext.count)
    XCTAssertEqual(secretboxString, expectedCiphertext)
    
    // decrypt
    let decrypted = try TweetNacl.open(message: secretbox, nonce: nonceData, publicKey: ephemPublicKeyData, secretKey: receiverKeys.secretKey)
    guard let decryptedMessage = String(data: decrypted, encoding: .utf8) else {
      XCTFail("Can't create a string")
      return
    }
    
    XCTAssertEqual(decryptedMessage, String(data: message, encoding: .utf8))
  }
}
