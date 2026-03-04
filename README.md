# Signature Verification Security Project

## Overview

This project demonstrates critical security vulnerabilities in smart contract signature verification and provides secure implementations to prevent common attack vectors. It focuses on the proper use of the `ecrecover` function in Solidity and highlights the importance of validating cryptographic signatures.

## Project Structure

### Smart Contracts ([/src](cci:9://file:///c:/Users/Admin/Desktop/Guille/Blockchain%20Accelerator/Bloque19/SignaturesOffchain/src:0:0-0:0))

#### 1. **SignatureAttacks.sol** - Vulnerable Implementation

This contract contains the `VulnerableSignatureContract`, which demonstrates a **critical security vulnerability** in signature verification.

**Key Functions:**

- **`authorizeUser(uint8 v, bytes32 r, bytes32 s, bytes32 hash, address user)`**: Authorizes a user based on a signature. **VULNERABLE** - does not validate that `ecrecover` returns a non-zero address, allowing attackers to bypass authorization with invalid signatures.

- **`recoverSigner(uint8 v, bytes32 r, bytes32 s, bytes32 hash)`**: Recovers the signer address from signature components. **VULNERABLE** - can return `address(0)` for invalid signatures without reverting.

- **`processData(string memory data)`**: Processes data for authorized users only.

- **`createAuthorizationHash(address user, uint256 nonce)`**: Creates a hash for authorization purposes.

**Vulnerability:** The contract fails to check if `ecrecover` returns `address(0)`, which occurs when signature validation fails. This allows attackers to gain unauthorized access by providing invalid signature components.

---

#### 2. **SecureSignatureContract.sol** - Secure Implementation

This contract demonstrates the **correct way** to handle signature verification with proper validation and security measures.

**Key Functions:**

- **`authorizeUser(uint8 v, bytes32 r, bytes32 s, bytes32 hash, address user)`**: Securely authorizes users by validating that `ecrecover` returns a valid address (`!= address(0)`).

- **`authorizeUserWithECDSA(bytes memory signature, bytes32 hash, address user)`**: Alternative implementation with additional security checks including:
  - Signature length validation
  - Signature malleability protection (validates `s` value)
  - `v` value validation (must be 27 or 28)
  - Replay attack protection

- **`recoverSigner(uint8 v, bytes32 r, bytes32 s, bytes32 hash)`**: Securely recovers signer address with proper validation, reverting on invalid signatures.

- **`processData(string memory data)`**: Processes data for authorized users only.

- **`createAuthorizationHash(address user, uint256 nonce)`**: Creates a hash for authorization purposes.

**Security Features:**
- ✅ Validates `ecrecover` result against `address(0)`
- ✅ Prevents signature malleability attacks
- ✅ Implements replay attack protection via hash tracking
- ✅ Validates signature component values

---

### Tests ([/test](cci:9://file:///c:/Users/Admin/Desktop/Guille/Blockchain%20Accelerator/Bloque19/SignaturesOffchain/test:0:0-0:0))

#### 1. **SignatureAttacks.t.sol** - Vulnerability Demonstration Tests

Tests that **demonstrate the vulnerability** in the insecure contract.

**Test Cases:**

- **`testValidSignature()`**: Verifies that legitimate signatures work correctly.

- **`testVulnerabilityWithInvalidSignature()`**: **Demonstrates the exploit** - shows that an attacker can gain authorization using completely invalid signature components (all zeros), which cause `ecrecover` to return `address(0)`.

- **`testVulnerabilityWithMalformedSignature()`**: Shows that malformed signatures (invalid `v` value of 255) also bypass security.

- **`testRecoverSignerWithInvalidSignature()`**: Confirms that `recoverSigner` returns `address(0)` for invalid signatures without reverting.

- **`testReplayAttack()`**: Verifies that replay attack protection works (hash reuse prevention).

- **`testProcessDataRequiresAuthorization()`**: Confirms authorization is required for data processing.

---

#### 2. **SecureSignatureAttacks.t.sol** - Security Validation Tests

Tests that **verify the security fixes** prevent the vulnerability.

**Test Cases:**

- **`testValidSignature()`**: Confirms legitimate signatures work correctly.

- **`testRejectsInvalidSignature()`**: Verifies that invalid signatures (all zeros) are **properly rejected** with the error message "Invalid signature".

- **`testRejectsMalformedSignature()`**: Confirms malformed signatures (invalid `v` value) are rejected.

- **`testRecoverSignerRejectsInvalidSignature()`**: Verifies that `recoverSigner` properly reverts on invalid signatures instead of returning `address(0)`.

- **`testReplayAttack()`**: Validates replay attack protection works correctly.

- **`testProcessDataRequiresAuthorization()`**: Confirms authorization requirements are enforced.

---

## Key Security Lessons

### The Vulnerability

The `ecrecover` precompile in Solidity returns `address(0)` when signature verification fails. Without proper validation, this can lead to:

- **Unauthorized access** by providing invalid signatures
- **Bypass of authentication mechanisms**
- **Critical security breaches** in authorization systems

### The Fix

Always validate `ecrecover` results:

```solidity
address signer = ecrecover(hash, v, r, s);
require(signer != address(0), "Invalid signature");
```
---
### Additional Best Practices
- Use OpenZeppelin's ECDSA library for production code
- Implement replay attack protection via nonce or hash tracking
- Validate signature malleability (check s value range)
- Validate v parameter (must be 27 or 28 for Ethereum signatures)
---
### Running tests
```bash
# Run all tests
forge test

# Run with verbosity
forge test -vvv

# Run specific test file
forge test --match-path test/SignatureAttacks.t.sol
forge test --match-path test/SecureSignatureAttacks.t.sol
```
---
*Educational Purpose*
This project is designed for educational purposes to demonstrate:
- How signature verification vulnerabilities occur
- The importance of proper input validation
- Secure coding practices for cryptographic operations
- The difference between vulnerable and secure implementations

*⚠️ Warning: Vulnerable contracts should never be used in production environments.*
