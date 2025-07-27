/* Pull the hex key out and strip the newline, then turn it into 32 raw bytes:
security find-generic-password \
  -s FreewriteEncryption \
  -a EncryptionKey \
  -w \
| tr -d '\n' \
| xxd -r -p \
> key.bin
*/

import { readFileSync, writeFileSync } from "fs";
import { createDecipheriv } from "crypto";

const decryptFile = (
  encryptedPath: string,
  keyPath: string,
  outputPath: string
): void => {
  const encryptedData = readFileSync(encryptedPath);
  const key = readFileSync(keyPath);
  if (key.length !== 32) {
    throw new Error(`Invalid key length: expected 32 bytes, got ${key.length}`);
  }

  // Parse CryptoKit’s combined format
  const iv = encryptedData.slice(0, 12); // first 12 bytes
  const tag = encryptedData.slice(encryptedData.length - 16); // last 16 bytes
  const ciphertext = encryptedData.slice(12, encryptedData.length - 16); // middle

  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  writeFileSync(outputPath, decrypted);
  console.log(`✅ Decrypted → ${outputPath}`);
};

// Example invocation
decryptFile("path-to-file", "key.bin", "journal.txt");
