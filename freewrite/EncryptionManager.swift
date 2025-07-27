//
//  EncryptionManager.swift
//  freewrite
//
//  Created by osada on 2/14/25.
//

import Foundation
import CryptoKit

// MARK: - Encryption Utilities
class EncryptionManager {
    private let authManager: AuthenticationManager
    
    init(authManager: AuthenticationManager) {
        self.authManager = authManager
    }
    
    func encrypt(data: Data) throws -> Data {
        print("EncryptionManager: Getting encryption key...")
        let key = try authManager.getEncryptionKey()
        print("EncryptionManager: Got encryption key, encrypting data...")
        let sealedBox = try AES.GCM.seal(data, using: key)
        let combined = sealedBox.combined!
        print("EncryptionManager: Encryption successful, combined size: \(combined.count) bytes")
        return combined
    }
    
    func decrypt(data: Data) throws -> Data {
        let key = try authManager.getEncryptionKey()
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(sealedBox, using: key)
    }
    
    func encryptString(_ string: String) throws -> Data {
        print("EncryptionManager: Attempting to encrypt string of length: \(string.count)")
        guard let data = string.data(using: .utf8) else {
            print("EncryptionManager: Failed to convert string to data")
            throw NSError(domain: "EncryptionError", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to convert string to data"])
        }
        print("EncryptionManager: String converted to data, size: \(data.count) bytes")
        let encryptedData = try encrypt(data: data)
        print("EncryptionManager: Successfully encrypted data, size: \(encryptedData.count) bytes")
        return encryptedData
    }
    
    func decryptToString(data: Data) throws -> String {
        let decryptedData = try decrypt(data: data)
        guard let string = String(data: decryptedData, encoding: .utf8) else {
            throw NSError(domain: "EncryptionError", code: -2, userInfo: [NSLocalizedDescriptionKey: "Failed to convert decrypted data to string"])
        }
        return string
    }
}
