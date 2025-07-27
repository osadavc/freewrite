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
import AppKit

// MARK: - Authentication and Encryption Manager
class AuthenticationManager: ObservableObject {
    @Published var isAuthenticated = false
    @Published var biometricType: LABiometryType = .none
    @Published var authenticationError: String?
    
    private let context = LAContext()
    private let keychainService = "FreewriteEncryption"
    private let keychainAccount = "EncryptionKey"
    
    // Cache the encryption key in memory after authentication
    private var cachedEncryptionKey: SymmetricKey?
    
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
                        // Load and cache the encryption key after successful authentication
                        loadEncryptionKey()
                    } else {
                        authenticationError = "Authentication failed"
                    }
                }
                return
            } catch {
                // Check if user cancelled biometric authentication
                if (error as NSError).code == -2 {
                    await MainActor.run {
                        print("User cancelled biometric authentication, quitting app")
                        NSApplication.shared.terminate(nil)
                    }
                    return
                }
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
                        // Load and cache the encryption key after successful authentication
                        loadEncryptionKey()
                    } else {
                        authenticationError = "Authentication failed"
                    }
                }
            } catch {
                await MainActor.run {
                    print("Authentication error: \(error)")
                    print("Error code: \(error._code)")
                    authenticationError = error.localizedDescription
                    isAuthenticated = false
                    
                    // Quit the app if user cancels authentication (LAError.userCancel = -2)
                    if (error as NSError).code == -2 {
                        print("User cancelled authentication, quitting app")
                        NSApplication.shared.terminate(nil)
                    }
                }
            }
        } else {
            await MainActor.run {
                authenticationError = "No authentication method available"
            }
        }
    }
    
    private func loadEncryptionKey() {
        do {
            cachedEncryptionKey = try getOrCreateEncryptionKey()
            print("AuthenticationManager: Encryption key loaded and cached")
        } catch {
            print("AuthenticationManager: Failed to load encryption key: \(error)")
            authenticationError = "Failed to load encryption key"
            isAuthenticated = false
        }
    }
    
    func getEncryptionKey() throws -> SymmetricKey {
        // Return cached key if available and authenticated
        if isAuthenticated, let cachedKey = cachedEncryptionKey {
            return cachedKey
        }
        
        // If not authenticated or no cached key, this shouldn't happen in normal flow
        throw NSError(domain: "AuthenticationError", code: -1, userInfo: [NSLocalizedDescriptionKey: "Not authenticated or encryption key not available"])
    }
    
    private func getOrCreateEncryptionKey() throws -> SymmetricKey {
        // Try to retrieve existing key from keychain
        if let existingKeyData = getKeychainData() {
            print("AuthenticationManager: Retrieved existing key from keychain")
            return SymmetricKey(data: existingKeyData)
        }
        
        // Create new key if none exists
        print("AuthenticationManager: Creating new encryption key")
        let newKey = SymmetricKey(size: .bits256)
        let keyData = newKey.withUnsafeBytes { Data($0) }
        
        // Store in keychain
        try storeKeychainData(keyData)
        print("AuthenticationManager: Stored key in keychain")
        
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
        // Store with basic device-only accessibility - no additional access control
        // Security is provided by our app-level authentication
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
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
            throw NSError(domain: "KeychainError", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Failed to store encryption key in Keychain - Status: \(status)"])
        }
    }
    
    func logout() {
        isAuthenticated = false
        cachedEncryptionKey = nil
        authenticationError = nil
        print("AuthenticationManager: User logged out, encryption key cleared from memory")
    }
}