# DCypher Public Audit TODO List

## Test Matrix: CLI ↔ TUI ↔ API Coverage (HIGHEST PRIORITY)

### Identity Management

| Operation | CLI Command | TUI Screen/Action | API Method | Test Coverage |
|-----------|-------------|-------------------|------------|---------------|
| Create Identity | `identity new` | Identity → `action_create_identity()` | `DCypherClient.create_identity_file()` | ✅ Tested |
| Load Identity | - | Identity → `action_load_identity()` | - | ✅ Tested |
| Browse Identity | - | Identity → `action_browse_identity()` | - | ❌ TODO |
| Migrate Identity | `identity migrate` | - | - | ⚠️ CLI only |
| Identity Info | `identity info` | - | - | ⚠️ CLI only |
| Rotate Keys | `identity rotate` | - | `KeyManager.rotate_keys_in_identity()` | ⚠️ CLI only |
| Backup Identity | `identity backup` | - | `KeyManager.backup_identity_securely()` | ⚠️ CLI only |

### Account Management

| Operation | CLI Command | TUI Screen/Action | API Method | Test Coverage |
|-----------|-------------|-------------------|------------|---------------|
| List Accounts | `list-accounts` | Accounts → `action_list_accounts()` | `list_accounts()` | ✅ Tested |
| Create Account | `create-account` | Accounts → `action_create_account()` | `create_account()` | ✅ Tested |
| Get Account | `get-account` | Accounts → `action_get_account()` | `get_account()` | ✅ Tested |
| List Files | `list-files` | Accounts → `action_list_files()` | `list_files()` | ✅ Tested |
| Get Graveyard | `get-graveyard` | Accounts → `action_get_graveyard()` | `get_account_graveyard()` | ❌ TODO |
| Add PQ Keys | `add-pq-keys` | Accounts → `action_add_pq_keys()` | `add_pq_keys()` | ✅ Tested |
| Remove PQ Keys | `remove-pq-keys` | Accounts → `action_remove_pq_keys()` | `remove_pq_keys()` | ✅ Tested |
| Supported Algs | `supported-algorithms` | Accounts → `action_supported_algorithms()` | `get_supported_algorithms()` | ✅ Tested |

### File Operations

| Operation | CLI Command | TUI Screen/Action | API Method | Test Coverage |
|-----------|-------------|-------------------|------------|---------------|
| Upload File | `upload` | Files → `action_upload_file()` | `register_file()` + `upload_chunk()` | ✅ Tested |
| Download File | `download` | Files → `action_download_file()` | `download_file()` | ✅ Tested |
| Download Chunks | `download-chunks` | - | `download_chunks()` | ⚠️ CLI only |
| Browse File | - | Files → `action_browse_file()` | - | ❌ TODO |

### PRE/Sharing Operations

| Operation | CLI Command | TUI Screen/Action | API Method | Test Coverage |
|-----------|-------------|-------------------|------------|---------------|
| Get PRE Context | `get-pre-context` | Sharing → `action_get_pre_context()` | `get_crypto_context_bytes()` | ✅ Tested |
| Init PRE | `init-pre` | Sharing → `action_init_pre()` | `initialize_pre_for_identity()` | ✅ Tested |
| Create Share | `create-share` | Sharing → `action_create_share()` | `create_share()` | ✅ Tested |
| List Shares | `list-shares` | Sharing → `action_list_shares()` | `list_shares()` | ✅ Tested |
| Download Shared | `download-shared` | Sharing → `action_download_shared()` | `download_shared_file()` | ✅ Tested |
| Revoke Share | `revoke-share` | Sharing → `action_revoke_share()` | `revoke_share()` | ✅ Tested |

### Crypto Operations

| Operation | CLI Command | TUI Screen/Action | API Method | Test Coverage |
|-----------|-------------|-------------------|------------|---------------|
| Generate CC | `gen-cc` | Crypto → `action_generate_crypto_context()` | - | ❌ TODO |
| Generate Keys | `gen-keys` | Crypto → `action_generate_keys()` | - | ❌ TODO |
| Generate Signing Keys | `gen-signing-keys` | Crypto → `action_generate_signing_keys()` | - | ❌ TODO |
| Encrypt | `encrypt` | Crypto → `action_encrypt()` | - | ❌ TODO |
| Decrypt | `decrypt` | Crypto → `action_decrypt()` | - | ❌ TODO |
| Generate Rekey | `gen-rekey` | Crypto → `action_generate_rekey()` | `generate_re_encryption_key()` | ❌ TODO |
| Re-encrypt | `re-encrypt` | Crypto → `action_re_encrypt()` | - | ❌ TODO |

## Critical Tasks (MUST land before audit)

### 1. Complete Missing TUI Implementations (Priority: CRITICAL)

- [ ] **Fix all `pass` statements in TUI screens** (src/tui/app.py lines 71, 141, 168-174, 260-286)
- [ ] **Implement Dashboard actions**:
  - [ ] `action_load_identity()` (line 144)
  - [ ] `action_upload_file()` (line 153)
  - [ ] `action_create_share()` (line 161)
  - [ ] `action_view_logs()` (line 166)
- [ ] **Implement Crypto screen** (Tab 3 - currently has no tests):
  - [ ] Encrypt/decrypt operations using loaded identity
  - [ ] Key generation workflows
  - [ ] Re-encryption key generation
- [ ] **Fix Identity screen browse dialog** (line 270)
- [ ] **Implement help screen** (F1 binding)
- [ ] **Implement logs screen** (F2 binding)

### 2. End-to-End Test Coverage (Priority: CRITICAL)

- [ ] **Dashboard tab (Tab 1) tests** - system status, shortcut buttons
- [ ] **Crypto tab (Tab 3) tests** - encrypt/decrypt with identity
- [ ] **Large file tests** (>100MB upload/download)
- [ ] **Network failure simulation tests**
- [ ] **Concurrent operations tests** (race conditions)
- [ ] **Replay attack tests**

### 3. Security & Protocol Validation (Priority: CRITICAL)

- [ ] **Remove debug print statements** that leak paths/keys
- [ ] **Add proper logging** with secret redaction
- [ ] **Path traversal prevention** validation
- [ ] **Input validation** for all TUI forms
- [ ] **Signature verification** error handling

### 4. Missing Functionality (Priority: CRITICAL)

- [ ] **Key rotation via TUI** (currently CLI only)
- [ ] **Identity backup via TUI** (currently CLI only)
- [ ] **Download chunks via TUI** (currently CLI only)
- [ ] **File browser implementation** for Files screen
- [ ] **Identity browser implementation** for Identity screen

## High Priority Tasks

### 5. Accessibility & Navigation (Priority: HIGH)

- [ ] **Command palette implementation** (`ctrl+\` binding)
- [ ] **Tab order validation** across all screens
- [ ] **ESC/Enter key handling** for all dialogs
- [ ] **Focus ring visibility** testing
- [ ] **Keyboard-only navigation tests**

### 6. Snapshot Testing (Priority: HIGH)

- [ ] **Install pytest-textual-snapshot**
- [ ] **Create snapshot tests for**:
  - [ ] Identity screen (empty, loaded)
  - [ ] Files screen (empty, with files)
  - [ ] Sharing screen (no shares, with shares)
  - [ ] Error states for each screen

### 7. Performance Testing (Priority: HIGH)

- [ ] **Encrypt performance**: 1MB, 10MB, 100MB files
- [ ] **Share creation performance** with large files
- [ ] **Download performance** for shared files
- [ ] **Assert time budgets** for each operation

### 8. Security Review (Priority: HIGH)

- [ ] **Run Bandit/Semgrep** static analysis
- [ ] **Fix high/medium findings**
- [ ] **Review temp file handling**
- [ ] **Check file permissions** (not world-readable)
- [ ] **Audit logging implementation**

## Medium Priority Tasks

### 9. UI Polish (Priority: MEDIUM)

- [ ] **Theme toggle implementation** (ctrl+d)
- [ ] **Transparency CSS** (ctrl+t)
- [ ] **Help screen content** with keybindings
- [ ] **Version/license info** in help screen
- [ ] **Error message clarity** improvements

### 10. API Improvements (Priority: MEDIUM)

- [ ] **Add Pydantic models** for API responses
- [ ] **Type all dict returns** with TypedDict
- [ ] **Consistent error responses**
- [ ] **API versioning** headers

### 11. Documentation (Priority: MEDIUM)

- [ ] **TUI user guide** with screenshots
- [ ] **API integration guide**
- [ ] **Security best practices** doc
- [ ] **Deployment guide** for production

## Low Priority Tasks

### 12. CI/CD Improvements (Priority: LOW)

- [ ] **Coverage badge** generation (target ≥90%)
- [ ] **Headless TUI testing** documentation
- [ ] **Snapshot generation** in CI
- [ ] **Lint/format enforcement** (ruff/black)

### 13. Developer Experience (Priority: LOW)

- [ ] **VS Code launch configs** for TUI debugging
- [ ] **Development setup script**
- [ ] **Test data generation** utilities
- [ ] **Performance profiling** setup

## Test Matrix Gaps to Address

### CLI-only Operations (need TUI support)

1. **Identity rotation** - Critical for key compromise scenarios
2. **Identity backup** - Critical for disaster recovery
3. **Identity migration** - Important for auth_keys → identity upgrades
4. **Download chunks** - Important for resumable downloads

### TUI-only Operations (need CLI support)

1. **Browse file dialog** - Nice to have
2. **Browse identity dialog** - Nice to have

### Missing Test Coverage

1. **Crypto tab operations** - No tests exist
2. **Dashboard tab operations** - Limited tests
3. **Graveyard operations** - No tests
4. **Browser dialogs** - No implementation

## Implementation Order

1. **Week 1**: Complete all CRITICAL missing implementations
2. **Week 1-2**: Add comprehensive test coverage for all tabs
3. **Week 2**: Security review and fixes
4. **Week 2-3**: Performance and accessibility testing
5. **Week 3**: Documentation and polish
6. **Final 2 days**: Code freeze and audit prep

## Success Criteria for Audit

- [ ] Zero `TODO` or `pass` statements in production paths
- [ ] 100% test coverage for happy paths
- [ ] All security findings addressed
- [ ] Performance benchmarks documented
- [ ] Complete user workflows tested end-to-end
- [ ] No debug prints or secret leaks
- [ ] All major operations available in both CLI and TUI

## Current Test Coverage Status

### Existing Test Files

- **API Tests**: Comprehensive coverage for accounts, files, PQ keys, chunks
  - `test_api_account_comprehensive.py` ✅
  - `test_api_files_comprehensive.py` ✅
  - `test_api_pqkeys.py` ✅
  - `test_chunk_upload.py` ✅

- **CLI Tests**: Good coverage for main workflows
  - `test_cli_comprehensive.py` ✅
  - `test_cli_workflows_full.py` ✅
  - `test_cli_files.py` ✅

- **TUI Tests**: Partial coverage, missing critical tabs
  - `test_tui_e2e_workflows.py` ✅
  - `test_tui_e2e_pre_share.py` ✅
  - `test_tui_e2e_pre_share_security.py` ✅
  - `test_tui_ui_components.py` ✅
  - `test_screens.py` ⚠️ (CryptoScreen tests commented out)

### Critical Test Gaps

1. **Crypto Tab**: Only basic initialization tests, no functional tests
2. **Dashboard Tab**: No dedicated test file
3. **Graveyard Operations**: No test coverage across CLI/TUI/API
4. **File Browser Dialogs**: Not implemented yet
5. **Large File Operations**: No stress tests for >100MB files
6. **Network Resilience**: No tests for connection failures/retries

### Test Infrastructure Notes

- Using `tui_test_helpers.py` with good async wait conditions ✅
- Snapshot testing not implemented yet (would catch UI regressions)
- Performance benchmarks not tracked in CI
