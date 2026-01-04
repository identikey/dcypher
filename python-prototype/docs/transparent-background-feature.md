# Transparent Background Feature

The dCypher TUI now supports transparent backgrounds for terminals that support transparency effects.

## Overview

This feature allows users to remove background colors from the TUI interface, making it possible to see through to:

- Desktop wallpapers
- Terminal background images
- Other terminal transparency effects
- Underlying applications (in transparent terminal emulators)

## How to Use

### Toggle Transparency

Press `Ctrl+T` to toggle between normal and transparent background modes.

### Visual Changes

**Normal Mode (default):**

- Dark gray backgrounds (`#1a1a1a`, `#2a2a2a`, `#3a3a3a`)
- Standard cyberpunk aesthetic with solid backgrounds
- Best for regular terminal usage

**Transparent Mode:**

- All backgrounds set to `transparent`
- Enhanced borders and text for visibility
- Cyberpunk colors and styling maintained
- Matrix green text and neon borders remain prominent

## Technical Implementation

### Theme System

The transparency feature uses a dynamic theme generation system:

```python
from src.tui.theme import get_cyberpunk_theme

# Normal theme
normal_theme = get_cyberpunk_theme(transparent_background=False)

# Transparent theme  
transparent_theme = get_cyberpunk_theme(transparent_background=True)
```

### Key Components

1. **Reactive Property**: `app.transparent_background` tracks current state
2. **Dynamic CSS**: Theme updates automatically when toggled
3. **Key Binding**: `Ctrl+T` for instant toggling
4. **Preserved Aesthetics**: Cyberpunk colors and borders maintained

### Color Preservation

Even in transparent mode, the following elements remain vibrant:

- **Matrix Green** (`#00ff41`) - Primary text and borders
- **Neon Orange** (`#ff6b35`) - Secondary accents
- **Cyan Blue** (`#00d4ff`) - Accent highlights
- **Electric Yellow** (`#ffff00`) - Warnings
- **Neon Red** (`#ff073a`) - Errors

## Terminal Compatibility

### Recommended Terminals

- **Alacritty** - Excellent transparency support
- **Kitty** - Built-in transparency features
- **iTerm2** (macOS) - Advanced transparency options
- **Windows Terminal** - Good transparency support
- **Terminator** - Configurable transparency

### Configuration Examples

**Alacritty** (`~/.config/alacritty/alacritty.yml`):

```yaml
background_opacity: 0.8
```

**Kitty** (`~/.config/kitty/kitty.conf`):

```
background_opacity 0.8
dynamic_background_opacity yes
```

**Windows Terminal** (settings.json):

```json
{
  "backgroundImageOpacity": 0.8,
  "useAcrylic": true,
  "acrylicOpacity": 0.8
}
```

## Use Cases

### Desktop Integration

- Show desktop wallpaper through terminal
- Create floating terminal effect
- Overlay terminal on other applications

### Development Workflow  

- Monitor multiple applications simultaneously
- Maintain visual connection to desktop
- Aesthetic preference for minimal interfaces

### Gaming/Streaming

- Overlay terminal during streams
- Gaming terminal that doesn't block view
- Cyberpunk aesthetic enhancement

## Best Practices

### Visibility Considerations

- Ensure terminal transparency isn't too high (recommend 70-90% opacity)
- Use dark or low-contrast backgrounds behind terminal
- Test readability with your specific wallpaper/background

### Performance

- Transparency has minimal performance impact
- Theme switching is instantaneous
- No additional system resources required

### Accessibility

- Normal mode available for users who need high contrast
- Text remains bold and well-defined in both modes
- Color scheme maintains accessibility standards

## Troubleshooting

### Text Hard to Read

- Reduce terminal transparency (increase opacity)
- Switch to normal mode with `Ctrl+T`
- Use darker desktop wallpaper
- Adjust terminal emulator contrast settings

### Transparency Not Working

- Verify terminal emulator supports transparency
- Check terminal configuration for opacity settings
- Some terminals require compositor (Linux)
- Windows may need DWM enabled

### Colors Look Different

- This is expected - backgrounds become transparent
- Text and borders remain the same cyberpunk colors
- Use `Ctrl+T` to compare normal vs transparent modes

## Testing

The feature includes comprehensive test coverage:

- Toggle functionality testing
- Theme generation verification  
- Key binding validation
- CSS property testing

Run tests with:

```bash
pytest tests/tui/test_navigation_fixes.py -k transparent -v
```

## Future Enhancements

Potential future improvements:

- Variable transparency levels (not just on/off)
- Per-widget transparency control
- Saved transparency preferences
- Terminal-specific optimization
