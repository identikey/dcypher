"""
Documentation Screen
Provides access to documentation, help content, and API references
"""

from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import Static, Button, DataTable, Label, TextArea, Select, Tree
from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from rich.text import Text
from rich.markdown import Markdown
from rich.table import Table
from typing import Dict, Any, Optional
from pathlib import Path


class DocsScreen(Widget):
    """
    Documentation screen providing help content, API references, and guides
    Designed like a file explorer with tree navigation
    """

    DEFAULT_CSS = """
    #docs-container {
        layout: horizontal;
        height: 100%;
        scrollbar-size: 1 1;
    }
    
    #docs-tree-panel {
        width: 30%;
        min-width: 25;
        background: $surface;
        border: double $primary;
        margin-left: 0;
        margin-top: 1;
        margin-bottom: 1;
        margin-right: 1;
    }
    
    #docs-tree {
        height: 100%;
        scrollbar-gutter: stable;
        scrollbar-background: $surface;
        scrollbar-color: $primary;
        scrollbar-size: 1 1;
        overflow-x: auto;
        overflow-y: auto;
        padding: 1;
    }
    
    #docs-content-panel {
        width: 70%;
        height: 100%;
        border: double $primary;
        margin: 1;
        background: $surface;
        scrollbar-size: 1 1;
    }
    
    #docs-content-display {
        height: 100%;
        width: 100%;
        border: none;
        background: transparent;
        margin: 1;
        scrollbar-size: 1 1;
    }
    """

    # Reactive state
    current_doc_content = reactive("")
    current_doc_type = reactive("overview")

    @property
    def current_identity_path(self):
        """Get current identity path from app state"""
        return getattr(self.app, "current_identity_path", None)

    @property
    def api_url(self):
        """Get API URL from app state"""
        return getattr(self.app, "api_url", "http://127.0.0.1:8000")

    @property
    def api_client(self):
        """Get API client from app"""
        get_client_method = getattr(self.app, "get_or_create_api_client", None)
        if get_client_method and callable(get_client_method):
            return get_client_method()
        return None

    def compose(self):
        """Compose the documentation interface like a file explorer"""
        with Container(id="docs-container"):
            with Horizontal():
                # Left sidebar - Documentation tree (file explorer style)
                with Container(id="docs-tree-panel"):
                    yield Tree("dCypher Documentation", id="docs-tree")

                # Right side - Documentation content area (main content)
                with Container(id="docs-content-panel"):
                    yield TextArea(
                        id="docs-content-display",
                        read_only=True,
                        show_line_numbers=False,
                    )

    def on_mount(self) -> None:
        """Initialize docs screen"""
        self.setup_documentation_tree()
        self.load_documentation("overview")

    def setup_documentation_tree(self) -> None:
        """Setup the documentation tree structure"""
        tree = self.query_one("#docs-tree", Tree)

        # Reduce indentation by setting guide_depth (default is 4)
        tree.guide_depth = 1

        # Build flatter documentation structure with minimal indentation
        root = tree.root

        # Direct root items - Getting Started
        root.add("Overview", data="overview", allow_expand=False)
        root.add("Quick Start", data="getting_started", allow_expand=False)
        root.add("Configuration", data="configuration", allow_expand=False)

        # Core Features - flat list
        root.add("Identity Management", data="identity", allow_expand=False)
        root.add("Crypto Operations", data="crypto", allow_expand=False)
        root.add("File Management", data="files", allow_expand=False)
        root.add("Account Management", data="accounts", allow_expand=False)
        root.add("Sharing & PRE", data="sharing", allow_expand=False)

        # Reference - flat list
        root.add("API Reference", data="api_reference", allow_expand=False)
        root.add("Keyboard Shortcuts", data="shortcuts", allow_expand=False)
        root.add("Troubleshooting", data="troubleshooting", allow_expand=False)

        # Project Docs - single level grouping
        project_docs = root.add("Project Docs", data=None, allow_expand=False)
        project_docs.add("Main README", data="file:./README.md", allow_expand=False)
        project_docs.add("TUI README", data="file:./TUI_README.md", allow_expand=False)
        project_docs.add(
            "Setup Notes", data="file:./SETUP_NOTES.md", allow_expand=False
        )
        project_docs.add(
            "Dev Environment", data="file:./README-dev-env.md", allow_expand=False
        )
        project_docs.add("TODO", data="file:./TODO.md", allow_expand=False)
        project_docs.add("All Hands", data="file:./ALLHANDS.md", allow_expand=False)
        project_docs.add(
            "Claude Instructions", data="file:./CLAUDE.md", allow_expand=False
        )

        # Tech Specs - single level grouping
        tech_specs = root.add("Tech Specs", data=None, allow_expand=False)
        tech_specs.add("System Spec", data="file:./docs/spec.md", allow_expand=False)
        tech_specs.add(
            "Agent Overview", data="file:./docs/overview.agent.md", allow_expand=False
        )
        tech_specs.add(
            "Testing Guide", data="file:./docs/testing-guide.md", allow_expand=False
        )
        tech_specs.add(
            "TUI Identity",
            data="file:./docs/tui-centralized-identity-summary.md",
            allow_expand=False,
        )
        tech_specs.add(
            "TUI Navigation",
            data="file:./docs/tui-navigation-fixes.md",
            allow_expand=False,
        )
        tech_specs.add(
            "Transparent BG",
            data="file:./docs/transparent-background-feature.md",
            allow_expand=False,
        )
        tech_specs.add(
            "Proxy Discovery",
            data="file:./docs/proxy-service-discovery.md",
            allow_expand=False,
        )

        # Planning - single level grouping
        planning = root.add("Planning", data=None, allow_expand=False)
        planning.add(
            "Migration TODO",
            data="file:./docs/plans/migration-todo-checklist.md",
            allow_expand=False,
        )
        planning.add(
            "OpenFHE Build",
            data="file:./docs/plans/openfhe-shared-library-build-plan.md",
            allow_expand=False,
        )
        planning.add(
            "Python to Zig",
            data="file:./docs/plans/python-to-zig-migration-strategy.md",
            allow_expand=False,
        )
        planning.add(
            "Unified Zig Build",
            data="file:./docs/plans/unified-zig-build-plan.md",
            allow_expand=False,
        )

        # Source Docs - single level grouping
        source_docs = root.add("Source Docs", data=None, allow_expand=False)
        source_docs.add(
            "HDPrint Overview",
            data="file:./src/dcypher/hdprint/README.txt",
            allow_expand=False,
        )
        source_docs.add(
            "HDPrint Technical",
            data="file:./src/dcypher/hdprint/README.hdprint.txt",
            allow_expand=False,
        )
        source_docs.add(
            "Paiready Overview",
            data="file:./src/dcypher/hdprint/README.paiready.txt",
            allow_expand=False,
        )
        source_docs.add(
            "HDPrint Attacks",
            data="file:./src/dcypher/hdprint/attacks/README.md",
            allow_expand=False,
        )

        # Other - flat items
        root.add(
            "Audit Tests",
            data="file:./tests/integration/AUDIT_READY_TESTS.md",
            allow_expand=False,
        )
        root.add(
            "OpenHands Instructions",
            data="file:./.openhands-instructions.md",
            allow_expand=False,
        )
        root.add("VHDL Parser", data="file:./vhdl_parser/README.md", allow_expand=False)

        # Expand all sections
        root.expand_all()

    def on_tree_node_selected(self, event) -> None:
        """Handle tree node selection"""
        if event.node.data:
            self.load_documentation(str(event.node.data))

    def on_tree_node_highlighted(self, event) -> None:
        """Handle tree node highlighting (arrow key navigation)"""
        if event.node.data:
            self.load_documentation(str(event.node.data))

    def load_file_content(self, file_path: str) -> str:
        """Load content from a file"""
        try:
            path = Path(file_path)
            if not path.exists():
                return f"Error: File not found - {file_path}"

            if not path.is_file():
                return f"Error: Path is not a file - {file_path}"

            # Try to read the file with UTF-8 encoding
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()

                # If file is empty
                if not content.strip():
                    return f"File is empty: {file_path}"

                return content

            except UnicodeDecodeError:
                # Try with different encoding if UTF-8 fails
                try:
                    with open(path, "r", encoding="latin-1") as f:
                        content = f.read()
                    return content
                except Exception as e:
                    return f"Error reading file {file_path}: {str(e)}"

        except Exception as e:
            return f"Error accessing file {file_path}: {str(e)}"

    def load_documentation(self, doc_type: str) -> None:
        """Load and display documentation content"""
        self.current_doc_type = doc_type

        # Check if this is a file reference
        if doc_type.startswith("file:"):
            file_path = doc_type[5:]  # Remove "file:" prefix
            content = self.load_file_content(file_path)
            title = f"{file_path}"
        else:
            # Documentation content dictionary for built-in docs
            docs_content = {
                "overview": self.get_overview_content(),
                "getting_started": self.get_getting_started_content(),
                "identity": self.get_identity_docs(),
                "crypto": self.get_crypto_docs(),
                "files": self.get_files_docs(),
                "accounts": self.get_accounts_docs(),
                "sharing": self.get_sharing_docs(),
                "api_reference": self.get_api_reference(),
                "shortcuts": self.get_shortcuts_docs(),
                "configuration": self.get_configuration_docs(),
                "troubleshooting": self.get_troubleshooting_docs(),
            }

            content = docs_content.get(
                doc_type, "Documentation not available for this section."
            )
            title = f"{doc_type.replace('_', ' ').title()}"

        self.current_doc_content = content

        # Update the display
        content_widget = self.query_one("#docs-content-display", TextArea)
        content_panel = self.query_one("#docs-content-panel", Container)

        # Set the border title
        content_panel.border_title = title

        # Set just the content without title header
        content_widget.text = content

        # Scroll to top
        content_widget.scroll_home(animate=False)

    def get_overview_content(self) -> str:
        """Get overview documentation content"""
        return """dCypher Terminal User Interface

A cyberpunk-inspired terminal interface for quantum-resistant encryption operations.

FEATURES:
• Identity Management - Create and manage cryptographic identities
• Crypto Operations - Encrypt, decrypt, and manage keys  
• File Management - Upload, download, and share files securely
• Account Management - Manage user accounts and post-quantum keys
• Sharing & PRE - Proxy re-encryption for secure sharing
• Real-time Monitoring - System stats and connection status

NAVIGATION:
Use Tab/Shift+Tab or arrow keys to navigate between tabs.
Press number keys (1-7) for quick tab access.

GETTING STARTED:
1. Connect to API server (Ctrl+R)
2. Create or load an identity (Identity tab)  
3. Begin cryptographic operations

Navigate the documentation tree on the left to explore different topics."""

    def get_getting_started_content(self) -> str:
        """Get getting started documentation"""
        return """Getting Started with dCypher TUI

INITIAL SETUP:
1. Start the TUI application
2. Connect to API server using Ctrl+R
3. Navigate to Identity tab (press 2)
4. Create a new identity or load existing one

FIRST OPERATIONS:
• Create Account (Accounts tab - press 4)
• Upload a file (Files tab - press 5)  
• Encrypt data (Crypto tab - press 3)
• Share files securely (Sharing tab - press 6)

CONNECTION STATUS:
The header shows connection uptime and server status.
Green indicators mean active connections.
Red indicators mean disconnected state.

IDENTITY MANAGEMENT:
Always ensure you have an identity loaded before operations.
Identities contain your cryptographic keys and are required
for most dCypher operations.

TROUBLESHOOTING:
• Check API server is running on configured port
• Verify identity file exists and is readable
• Check network connectivity
• Review logs (F2) for detailed error information"""

    def get_identity_docs(self) -> str:
        """Get identity management documentation"""
        return """Identity Management

Identities are cryptographic profiles containing your keys and metadata.

OPERATIONS:
• Create Identity - Generate new cryptographic identity
• Load Identity - Load existing identity from file
• Rotate Keys - Update cryptographic keys for security
• Backup Identity - Create secure backup of identity
• Initialize PRE - Enable proxy re-encryption capabilities

KEY TYPES:
• Classic Keys - ECDSA keys for traditional operations
• Post-Quantum Keys - Quantum-resistant cryptographic keys
• PRE Keys - Proxy re-encryption keys for sharing

SECURITY BEST PRACTICES:
• Regularly rotate keys (recommended monthly)
• Keep secure backups of identity files
• Never share private key material
• Use strong, unique passwords for key encryption

FILE LOCATIONS:
Identity files are stored in JSON format containing
encrypted key material and metadata.

ADVANCED FEATURES:
• Automated key rotation with configurable schedules
• Secure backup creation with encryption
• PRE capability initialization for secure sharing
• Multi-algorithm support for quantum resistance"""

    def get_crypto_docs(self) -> str:
        """Get crypto operations documentation"""
        return """Cryptographic Operations

Core encryption and decryption capabilities.

OPERATIONS:
• Generate Context - Create cryptographic context
• Generate Keys - Create new key pairs  
• Encrypt - Secure data with quantum-resistant encryption
• Decrypt - Recover original data from ciphertext
• Generate Rekey - Create re-encryption keys
• Recrypt - Transform ciphertext for new recipients

ENCRYPTION MODES:
• Classical - Traditional ECDSA-based encryption
• Post-Quantum - Quantum-resistant algorithms
• Hybrid - Combination of classical and PQ methods

SUPPORTED ALGORITHMS:
• Kyber - Key encapsulation mechanism
• Dilithium - Digital signatures
• SPHINCS+ - Hash-based signatures  
• Falcon - Lattice-based signatures

DATA FORMATS:
Input and output can be text or binary data.
Results are typically base64-encoded for transport.

WORKFLOW:
1. Generate or load cryptographic context
2. Create key pairs for encryption operations
3. Encrypt sensitive data using hybrid methods
4. Securely transmit or store encrypted data
5. Decrypt data when needed with proper keys"""

    def get_files_docs(self) -> str:
        """Get file management documentation"""
        return """File Management

Upload, download, and manage files securely.

OPERATIONS:
• Upload File - Store encrypted files on server
• Download File - Retrieve and decrypt files
• Download Chunks - Stream large files in chunks
• Browse Files - View available files

UPLOAD PROCESS:
1. Select file using Browse or enter path
2. File is encrypted before upload
3. Progress bar shows upload status
4. File hash provided for future downloads

DOWNLOAD MODES:
• Standard - Full file download and decryption
• Compressed - Download with compression
• Chunks - Stream large files progressively

SECURITY:
• All files encrypted before upload
• Only identity owner can decrypt files
• File sharing available through PRE system
• File integrity verified with cryptographic hashes

FILE TABLE:
Shows filename, hash, size, upload date, and status
for all accessible files.

BEST PRACTICES:
• Regular file backups
• Verify file integrity after downloads
• Use compression for large files
• Monitor storage quotas"""

    def get_accounts_docs(self) -> str:
        """Get account management documentation"""
        return """Account Management

Manage user accounts and cryptographic capabilities.

OPERATIONS:
• List Accounts - View all available accounts
• Create Account - Register new user account  
• Get Account - Retrieve account information
• Add PQ Keys - Enable post-quantum capabilities
• Remove PQ Keys - Disable PQ algorithms
• Supported Algorithms - View available crypto algorithms

ACCOUNT TYPES:
• Standard - Basic account with classical crypto
• Post-Quantum - Enhanced with quantum-resistant keys
• Enterprise - Advanced features for organizations

POST-QUANTUM ALGORITHMS:
• Falcon-512 - Compact lattice signatures
• SPHINCS+-SHA2-128f - Hash-based signatures
• Dilithium2/3 - Module lattice signatures

ACCOUNT INFORMATION:
Accounts store public keys, algorithm preferences,
and metadata for secure communications.

PUBLIC KEY MANAGEMENT:
Share public keys for secure communication.
Never share private key material.

ACCOUNT SECURITY:
• Regular key rotation
• Multi-algorithm support
• Secure key storage
• Access control management"""

    def get_sharing_docs(self) -> str:
        """Get sharing and PRE documentation"""
        return """Sharing & Proxy Re-Encryption (PRE)

Securely share encrypted data without exposing private keys.

PRE CONCEPT:
Proxy Re-Encryption allows encrypted data to be
transformed for new recipients without decryption.

OPERATIONS:
• Initialize PRE - Set up PRE capabilities
• Create Share - Share file with specific recipient
• Download Shared - Access files shared with you
• Revoke Share - Remove access to shared files
• List Shares - View all active shares

SHARING PROCESS:
1. Initialize PRE for your identity
2. Upload encrypted file
3. Create share with recipient's public key
4. Recipient can download and decrypt

SECURITY FEATURES:
• No private key exposure during sharing
• Cryptographic access control
• Revocable permissions
• Audit trail for all shares

SHARE TYPES:
• File Shares - Share specific encrypted files
• Temporary - Time-limited access
• Permanent - Long-term sharing arrangements

ADVANCED FEATURES:
• Group sharing capabilities
• Access delegation
• Share expiration management
• Audit logging and monitoring"""

    def get_api_reference(self) -> str:
        """Get API reference documentation"""
        return """API Reference

dCypher REST API endpoints and usage.

BASE URL:
Default: http://127.0.0.1:8000
Configurable via --api-url parameter

AUTHENTICATION:
Most endpoints require identity-based authentication
using cryptographic signatures.

CORE ENDPOINTS:

HEALTH & STATUS:
• GET /health - Server health and uptime
• GET /nonce - Get authentication nonce

ACCOUNT MANAGEMENT:
• POST /accounts - Create new account
• GET /accounts - List accounts
• GET /accounts/{pubkey} - Get specific account
• POST /accounts/{pubkey}/pq-keys - Add PQ keys
• DELETE /accounts/{pubkey}/pq-keys - Remove PQ keys

FILE OPERATIONS:
• POST /files - Upload encrypted file
• GET /files - List available files
• GET /files/{hash} - Download specific file

SHARING & PRE:
• POST /shares - Create file share
• GET /shares - List active shares
• DELETE /shares/{id} - Revoke share

RESPONSE FORMATS:
All responses in JSON format.
Binary data base64-encoded.
Error responses include error codes and messages.

RATE LIMITING:
API enforces rate limits to prevent abuse.
Limits vary by endpoint and user type.

ERROR CODES:
• 200 - Success
• 400 - Bad Request  
• 401 - Unauthorized
• 404 - Not Found
• 500 - Server Error"""

    def get_shortcuts_docs(self) -> str:
        """Get keyboard shortcuts documentation"""
        return """Keyboard Shortcuts

Quick access to dCypher TUI features.

GLOBAL SHORTCUTS:
• Ctrl+C - Quit application
• Ctrl+R - Connect to server
• Ctrl+Shift+R - Disconnect from server
• F1 - Show help
• F2 - Show logs  
• F12 - Take screenshot

NAVIGATION:
• Tab - Next tab
• Shift+Tab - Previous tab
• Left Arrow - Previous tab
• Right Arrow - Next tab
• 1-7 - Quick tab access

TAB SHORTCUTS:
• 1 - Dashboard
• 2 - Identity
• 3 - Crypto
• 4 - Accounts
• 5 - Files
• 6 - Sharing
• 7 - Docs (this tab)

VISUAL EFFECTS:
• F3 - Toggle matrix rain background
• F4 - Toggle scrolling code background
• + or = - Increase matrix animation framerate
• - - Decrease matrix animation framerate

TREE NAVIGATION (Docs tab):
• Up/Down arrows - Navigate tree items
• Enter - Select/expand tree node
• Space - Toggle tree node expansion

TAB-SPECIFIC:
Each tab may have additional shortcuts.
Check individual tab documentation for specific bindings.

CUSTOMIZATION:
Shortcuts can be customized in configuration files.
See Configuration documentation for details."""

    def get_configuration_docs(self) -> str:
        """Get configuration documentation"""
        return """Configuration

Customize dCypher TUI behavior and appearance.

COMMAND LINE OPTIONS:
• --identity-path - Default identity file path
• --api-url - API server URL (default: http://127.0.0.1:8000)
• --profile - Enable performance profiling
• --profile-animations - Profile animation performance

CONFIGURATION FILES:
Settings stored in JSON format.
Default location: ~/.dcypher/config.json

CONFIGURATION STRUCTURE:
{
  "api": {
    "url": "http://127.0.0.1:8000",
    "timeout": 30,
    "retries": 3
  },
  "identity": {
    "default_path": "~/.dcypher/identity.json",
    "backup_dir": "~/.dcypher/backups"
  },
  "ui": {
    "theme": "cyberpunk",
    "matrix_effects": true,
    "animation_speed": 1.0
  }
}

APPEARANCE SETTINGS:
• Theme - Dark/light mode
• Matrix effects - Background animations
• Color scheme - Cyberpunk color palette
• Animation speed - Matrix rain framerate

CONNECTION SETTINGS:
• API URL - Server endpoint
• Timeout - Request timeout values
• Retry attempts - Failed request retries
• SSL verification - Certificate validation

IDENTITY SETTINGS:
• Default identity path
• Backup directory
• Key rotation schedule
• Security preferences

PERFORMANCE SETTINGS:
• Update intervals for system monitoring
• Profiling options
• Memory usage limits
• CPU usage optimization"""

    def get_troubleshooting_docs(self) -> str:
        """Get troubleshooting documentation"""
        return """Troubleshooting

Common issues and solutions.

CONNECTION ISSUES:
Problem: Cannot connect to API server
Solution: 
- Verify server is running on correct port
- Check API URL configuration (default: :8000)
- Verify network connectivity
- Review firewall settings
- Check server logs for errors

IDENTITY ISSUES:
Problem: Cannot load identity file
Solution:
- Check file exists and is readable
- Verify file format is valid JSON
- Check file permissions (should be 600)
- Try creating new identity
- Verify file is not corrupted

PERFORMANCE ISSUES:
Problem: TUI running slowly
Solution:
- Disable matrix animations (F3, F4)
- Reduce animation framerate (-)
- Check system resources (CPU, memory)
- Enable profiling to identify bottlenecks
- Close unnecessary applications

CRYPTO ERRORS:
Problem: Encryption/decryption fails
Solution:
- Verify identity is loaded
- Check key compatibility
- Ensure proper algorithm support
- Review error logs (F2)
- Verify API server crypto capabilities

FILE OPERATIONS:
Problem: Upload/download failures  
Solution:
- Check file permissions
- Verify disk space availability
- Ensure API connectivity
- Review file size limits
- Check network stability

COMMON ERROR MESSAGES:
• "Identity not loaded" - Load identity file first
• "API connection failed" - Check server status
• "Invalid key format" - Verify identity file integrity
• "Permission denied" - Check file permissions
• "Network timeout" - Check connection stability

LOG FILES:
Enable detailed logging for troubleshooting:
- Application logs via F2
- Server logs on API server
- System logs for resource issues
- Network logs for connectivity problems

GETTING HELP:
- Use F1 for context-sensitive help
- Check this documentation tree
- Review API server documentation
- Check GitHub issues for known problems"""
