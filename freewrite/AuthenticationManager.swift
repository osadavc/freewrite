//
//  AuthenticationManager.swift
//  freewrite
//
//  Created by osada on 2/14/25.
//

import Foundation
import LocalAuthentication
import Security
import CryptoKit

// MARK: - Authentication and Encryption Manager
class AuthenticationManager: ObservableObject {
    @Published var isAuthenticated = false
    @Published var biometricType: LABiometryType = .none
    @Published var authenticationError: String?
    
    private let context = LAContext()
    private let keychainService = "FreewriteEncryption"
    private let keychainAccount = "EncryptionKey"
    
    init() {
        checkBiometricAvailability()
    }
    
    func checkBiometricAvailability() {
        var error: NSError?
        
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            biometricType = context.biometryType
        } else {
            biometricType = .none
            authenticationError = error?.localizedDescription
        }
    }
    
    func authenticate() async {
        // First try biometric authentication
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) {
            do {
                let success = try await context.evaluatePolicy(
                    .deviceOwnerAuthenticationWithBiometrics,
                    localizedReason: "Authenticate to access your private journal entries"
                )
                
                await MainActor.run {
                    if success {
                        isAuthenticated = true
                        authenticationError = nil
                    } else {
                        authenticationError = "Authentication failed"
                    }
                }
                return
            } catch {
                // Fall through to device passcode authentication
            }
        }
        
        // Fall back to device passcode authentication
        if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) {
            do {
                let success = try await context.evaluatePolicy(
                    .deviceOwnerAuthentication,
                    localizedReason: "Authenticate to access your private journal entries"
                )
                
                await MainActor.run {
                    if success {
                        isAuthenticated = true
                        authenticationError = nil
                    } else {
                        authenticationError = "Authentication failed"
                    }
                }
            } catch {
                await MainActor.run {
                    authenticationError = error.localizedDescription
                    isAuthenticated = false
                }
            }
        } else {
            await MainActor.run {
                authenticationError = "No authentication method available"
            }
        }
    }
    
    func getOrCreateEncryptionKey() throws -> SymmetricKey {
        // Try to retrieve existing key from keychain first
        if let existingKeyData = getKeychainData() {
            print("AuthenticationManager: Retrieved existing key from keychain")
            return SymmetricKey(data: existingKeyData)
        }
        
        // Try to retrieve key from UserDefaults as fallback
        if let storedKeyData = UserDefaults.standard.data(forKey: "EncryptionKey") {
            print("AuthenticationManager: Retrieved existing key from UserDefaults")
            return SymmetricKey(data: storedKeyData)
        }
        
        // Create new key if none exists
        print("AuthenticationManager: Creating new encryption key")
        let newKey = SymmetricKey(size: .bits256)
        let keyData = newKey.withUnsafeBytes { Data($0) }
        
        // Try to store in keychain first, fall back to UserDefaults
        do {
            try storeKeychainData(keyData)
            print("AuthenticationManager: Stored key in keychain")
        } catch {
            print("AuthenticationManager: Keychain storage failed (\(error)), using UserDefaults")
            UserDefaults.standard.set(keyData, forKey: "EncryptionKey")
        }
        
        return newKey
    }
    
    private func getKeychainData() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        if status == errSecSuccess {
            return result as? Data
        }
        return nil
    }
    
    private func storeKeychainData(_ data: Data) throws {
        // Try to create access control with biometric authentication first
        var accessControl: SecAccessControl?
        var error: Unmanaged<CFError>?
        
        accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryAny,
            &error
        )
        
        // If biometric access control fails, fall back to basic authentication
        if accessControl == nil {
            accessControl = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                .devicePasscode,
                &error
            )
        }
        
        // If that also fails, use no access control (for development)
        let query: [String: Any]
        if let accessControl = accessControl {
            query = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: keychainService,
                kSecAttrAccount as String: keychainAccount,
                kSecValueData as String: data,
                kSecAttrAccessControl as String: accessControl
            ]
        } else {
            query = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: keychainService,
                kSecAttrAccount as String: keychainAccount,
                kSecValueData as String: data,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            ]
        }
        
        // Delete existing item first
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        
        // Add new item
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: "KeychainError", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Failed to store encryption key - Status: \(status)"])
        }
    }
}