# dCypher TUI - Cyberpunk Terminal Interface

A quantum-resistant encryption Terminal User Interface (TUI) inspired by cyberpunk aesthetics, btop system monitoring, and art deco design principles.

## 🎨 Design Philosophy

The dCypher TUI combines:

- **Cyberpunk/Cypherpunk** aesthetics with @repligate styling
- **btop-inspired** real-time system monitoring
- **Art Deco** design influences for elegant borders and layouts
- **Matrix-style** animations and effects
- **Quantum-resistant** cryptography focus

## 🚀 Features

### Core Functionality

- ✅ **Full CLI Feature Parity** - All CLI commands available in interactive form
- ✅ **Real-time Monitoring** - System resources and crypto operations
- ✅ **Interactive Dashboard** - Quick access to common operations
- ✅ **Tabbed Interface** - Organized by functional areas
- ✅ **Rich Widgets** - Advanced terminal UI components

### Visual Design

- 🎨 **Cyberpunk Color Scheme** - Matrix green, neon colors, dark backgrounds
- 🖥️ **ASCII Art Banners** - dCypher branding with multiple styles
- 🔲 **Custom Borders** - Art deco and cyberpunk patterns
- 📊 **System Monitoring** - btop-style CPU, memory, disk, network displays
- 🌈 **Matrix Rain Effects** - Animated background elements

### Screens & Operations

- **Dashboard** - System overview and quick actions
- **Identity** - Identity management, creation, loading, rotation
- **Crypto** - Encryption, decryption, key generation operations
- **Accounts** - Account management and post-quantum key operations
- **Files** - File upload, download, and management
- **Sharing** - Proxy recryption sharing operations

## 🛠️ Installation & Usage

### Prerequisites

```bash
# Install with textual support
uv add textual[syntax]
```

### Launch TUI

```bash
# From CLI
dcypher tui

# With options
dcypher tui --identity-path /path/to/identity.json
dcypher tui --api-url https://api.example.com
dcypher tui --theme cyberpunk

# Direct launch
uv run python -m src.tui_main
```

### Key Bindings

- `Ctrl+C` - Exit application
- `Ctrl+D` - Toggle dark mode
- `F1` - Help screen
- `F2` - Toggle system monitor
- `F12` - Screenshot
- `Tab` - Navigate between screens

## 🎯 Architecture

### Project Structure

```
src/tui/
├── app.py              # Main TUI application
├── theme.py            # Cyberpunk CSS theme
├── widgets/            # Custom widgets
│   ├── ascii_art.py    # ASCII banners and borders
│   └── system_monitor.py # System and crypto monitoring
└── screens/            # Individual screens
    ├── dashboard.py    # Main dashboard
    ├── identity.py     # Identity management
    ├── crypto.py       # Crypto operations
    ├── accounts.py     # Account management
    ├── files.py        # File operations
    └── sharing.py      # Sharing operations
```

### Key Components

#### Main Application (`app.py`)

- Textual-based application framework
- Tab management and navigation
- Real-time updates and monitoring
- State management across screens

#### Cyberpunk Theme (`theme.py`)

- Complete CSS theme with cyberpunk colors
- Matrix green (#00ff41) primary color
- Replicant amber (#ffb000) accents
- Art deco border patterns
- Dark backgrounds with neon highlights

#### Widgets (`widgets/`)

- **ASCIIBanner** - dCypher branding with animations
- **SystemMonitor** - btop-inspired system monitoring
- **CryptoMonitor** - Real-time crypto operation tracking
- **CyberpunkBorder** - Custom border patterns
- **MatrixRain** - Animated background effects

#### Screens (`screens/`)

Each screen provides full feature parity with CLI commands:

- Interactive forms and controls
- Real-time status updates
- Data tables and visualizations
- Progress indicators and notifications

## 🎨 Color Palette

| Color | Hex | Usage |
|-------|-----|-------|
| Matrix Green | `#00ff41` | Primary, success states |
| Neon Orange | `#ff6b35` | Secondary, warnings |
| Cyan Blue | `#00d4ff` | Accents, info |
| Electric Yellow | `#ffff00` | Highlights, alerts |
| Neon Red | `#ff073a` | Errors, critical |
| Bright Green | `#39ff14` | Active states |
| Replicant Amber | `#ffb000` | @repligate styling |
| Deep Black | `#0a0a0a` | Background |
| Dark Gray | `#1a1a1a` | Panels |

## 🧪 Testing

### Run Tests

```bash
# Simple component tests
uv run python test_tui_simple.py

# Full test suite (requires crypto setup)
uv run pytest tests/tui/ -v
```

### Demo

```bash
# Interactive demo
uv run python demo_tui.py
```

## 🔧 Development

### Adding New Screens

1. Create screen class in `src/tui/screens/`
2. Inherit from `Widget` or `Screen`
3. Implement `compose()` method for layout
4. Add event handlers for interactions
5. Register in main app tabs

### Custom Widgets

1. Create widget class in `src/tui/widgets/`
2. Inherit from appropriate Textual widget
3. Implement `render()` or `compose()` methods
4. Add reactive properties for state management
5. Include in theme CSS if needed

### Theme Customization

- Edit `src/tui/theme.py`
- Follow cyberpunk color scheme
- Use CSS variables for consistency
- Test with different terminal themes

## 📊 Performance

### System Requirements

- Python 3.8+
- Terminal with 256+ colors
- Minimum 80x24 terminal size
- ~10MB RAM for TUI components

### Optimization

- Efficient widget updates (2-5 second intervals)
- Lazy loading of heavy operations
- Minimal CPU usage when idle
- Responsive design for different terminal sizes

## 🎪 Features in Detail

### Dashboard Screen

- **System Monitor** - Real-time CPU, memory, disk, network
- **Crypto Monitor** - Active operations, completion rates
- **Status Panels** - Identity, API connection, file counts
- **Quick Actions** - Load identity, upload files, create shares

### Identity Management

- **Create Identity** - New quantum-safe identities
- **Load Identity** - Browse and load existing identities
- **Identity Info** - View keys, algorithms, capabilities
- **Key Rotation** - Rotate keys for security
- **Backup** - Secure identity backups

### Crypto Operations

- **Key Generation** - Classic and post-quantum keys
- **Encryption** - File and data encryption
- **Decryption** - Decrypt with proper keys
- **Recryption** - Proxy recryption operations
- **Algorithm Support** - Multiple PQ algorithms

### File Management

- **Upload** - Secure file upload with progress
- **Download** - File retrieval and verification
- **Chunked Operations** - Large file support
- **File Browser** - Navigate and select files
- **Metadata** - File information and sharing status

### Sharing Operations

- **PRE Initialization** - Set up proxy recryption
- **Create Shares** - Share files with specific recipients
- **Manage Shares** - View, modify, revoke shares
- **Share Browser** - Browse available shared files
- **Access Control** - Fine-grained permissions

## 🔮 Future Enhancements

### Planned Features

- [ ] **Matrix Rain Animation** - Full-screen background effects
- [ ] **Sound Effects** - Cyberpunk audio feedback
- [ ] **Plugin System** - Extensible widget architecture
- [ ] **Themes** - Multiple visual themes
- [ ] **Scripting** - Automation and batch operations
- [ ] **Network Visualization** - Connection graphs
- [ ] **Advanced Monitoring** - Detailed system metrics
- [ ] **Mobile Support** - Responsive design for small screens

### Technical Improvements

- [ ] **Performance Profiling** - Optimize rendering
- [ ] **Memory Management** - Reduce resource usage
- [ ] **Error Handling** - Comprehensive error recovery
- [ ] **Logging** - Detailed operation logs
- [ ] **Configuration** - User preferences and settings
- [ ] **Accessibility** - Screen reader support
- [ ] **Internationalization** - Multi-language support

## 🤝 Contributing

### Development Setup

```bash
# Clone and setup
git clone <repository>
cd dcypher
uv sync

# Install TUI dependencies
uv add textual[syntax]

# Run tests
uv run python test_tui_simple.py

# Launch TUI
uv run python -m src.tui_main
```

### Code Style

- Follow existing cyberpunk aesthetic
- Use descriptive variable names
- Add docstrings for all classes/methods
- Include type hints where appropriate
- Test all new components

### Pull Requests

- Include screenshots of UI changes
- Test on multiple terminal types
- Update documentation
- Add tests for new features
- Follow commit message conventions

## 📜 License

Same as main dCypher project - see LICENSE file.

## 🎭 Credits

- **Textual** - Modern TUI framework
- **Rich** - Terminal formatting and styling
- **btop** - System monitoring inspiration
- **@repligate** - Cyberpunk aesthetic inspiration
- **Blade Runner** - Art deco and replicant themes
- **The Matrix** - Green rain and terminal aesthetics

---

*"The future is not some place we are going, but one we are creating. The paths are not to be found, but made. And the activity of making them changes both the maker and the destination."* - John Schaar

**dCypher TUI - Where quantum cryptography meets cyberpunk aesthetics.**
