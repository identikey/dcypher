"""
Cyberpunk theme for dCypher TUI
Inspired by: Matrix, Blade Runner, @repligate aesthetics, art deco elements
"""


def get_cyberpunk_theme(transparent_background: bool = False) -> str:
    """
    Generate cyberpunk theme CSS with optional transparent backgrounds

    Args:
        transparent_background: If True, removes background colors for terminal transparency
    """
    # Base colors remain the same
    base_colors = """
/* Global Variables - Cyberpunk Color Palette */
$primary: #00ff41;        /* Matrix green */
$secondary: #ff6b35;      /* Neon orange */
$accent: #00d4ff;         /* Cyan blue */
$warning: #ffff00;        /* Electric yellow */
$error: #ff073a;          /* Neon red */
$success: #39ff14;        /* Bright green */
"""

    if transparent_background:
        # Transparent mode - no backgrounds, enhanced borders and text
        background_vars = """
$bg-dark: transparent;
$bg-medium: transparent;
$bg-light: transparent;
$text-primary: #00ff41;   /* Matrix green text */
$text-secondary: #ffffff; /* White text */
$text-dim: #888888;       /* Dim gray */

$border-primary: #00ff41; /* Matrix green border */
$border-secondary: #ff6b35; /* Orange border */
"""
    else:
        # Normal mode with dark backgrounds
        background_vars = """
$bg-dark: #1a1a1a;        /* Dark gray (lightened) */
$bg-medium: #2a2a2a;      /* Medium gray */
$bg-light: #3a3a3a;       /* Light gray */
$text-primary: #00ff41;   /* Matrix green text */
$text-secondary: #ffffff; /* White text */
$text-dim: #888888;       /* Dim gray */

$border-primary: #00ff41; /* Matrix green border */
$border-secondary: #ff6b35; /* Orange border */
"""

    # Common styles that work for both modes
    common_styles = """
/* App-wide styles */
App {
    background: $bg-dark;
    color: $text-primary;
}

/* Header styling - @repligate inspired */
Header {
    background: $bg-medium;
    color: $text-primary;
    border: solid $border-primary;
    text-style: bold;
    height: 3;  /* Ensure header is tall enough for title + subtitle */
    min-height: 3;
}

Header .header--title {
    color: $primary;
    text-style: bold;
}

Header .header--clock {
    color: $accent;
    text-style: bold;
}

/* Footer styling */
Footer {
    background: $bg-medium;
    color: $text-secondary;
    border: solid $border-primary;
    text-style: bold;
    height: 3;  /* Ensure footer is tall enough for keybindings */
    min-height: 3;
}

/* Process monitoring dividers */
#cpu-divider {
    height: 5;
    min-height: 5;
    background: $bg-dark;
    color: $accent;
    text-style: bold;
    margin: 0;
    padding: 0;
}

#cpu-divider > Vertical {
    height: 100%;
    margin: 0;
    padding: 0;
}

#cpu-sparkline {
    height: 5;
    min-height: 5;
    background: $bg-dark;
    padding: 0;
}

#cpu-sparkline > .sparkline--max-color {
    color: $accent;
}

#cpu-sparkline > .sparkline--min-color {
    color: $accent 30%;
}

#cpu-sparkline-1min {
    height: 1fr;
    min-height: 4;
    max-height: 4;
    background: $bg-dark;
    padding: 0;
    margin: 0;
    border: none;
    outline: none;
}

#cpu-sparkline-1min > .sparkline--max-color {
    color: $accent;
}

#cpu-sparkline-1min > .sparkline--min-color {
    color: $accent 30%;
}

#cpu-sparkline-5min {
    height: 1fr;
    min-height: 4;
    max-height: 4;
    background: $bg-dark;
    padding: 0;
    margin: 0;
    border: none;
    outline: none;
}

#cpu-sparkline-5min > .sparkline--max-color {
    color: $primary;
}

#cpu-sparkline-5min > .sparkline--min-color {
    color: $primary 30%;
}

#memory-divider {
    height: auto;
    min-height: 3;
    max-height: 5;
    background: $bg-dark;
    color: $warning;
    text-style: bold;
    margin: 0;
    padding: 0;
    border: double $warning;
}

/* ASCII Banner styling */
ASCIIBanner {
    height: 12;
    background: $bg-medium;
    color: $primary;
    text-style: bold;
    text-align: center;
    border: solid $border-primary;
}

/* Main container */
#main-container {
    background: $bg-medium;
    border: solid $border-primary;
    margin: 1;
    padding: 1;
}

/* Tabbed content styling */
TabbedContent {
    border: solid $border-primary;
    height: 100%;
}

TabbedContent > Tabs {
    background: $bg-medium;
    color: $text-primary;
    height: 3;  /* Fixed height for tab headers */
}

TabbedContent > Tabs > Tab {
    background: $bg-dark;
    color: $text-dim;
    border: solid $border-primary;
    text-style: bold;
}

TabbedContent > Tabs > Tab.-active {
    background: $primary;
    color: $bg-dark;
    text-style: bold;
}

TabbedContent > ContentSwitcher {
    border: solid $border-primary;
    height: 1fr;  /* Take remaining space after tabs */
    min-height: 10;  /* Ensure minimum content height */
}

/* TabPane content areas */
TabPane {
    height: 100%;
    min-height: 8;  /* Ensure content has minimum height */
}

/* Screen widgets inside tabs */
DashboardScreen, IdentityScreen, CryptoScreen, AccountsScreen, FilesScreen, SharingScreen {
    background: $bg-medium;
    height: 100%;
    padding: 1;
}

/* Dashboard specific styling */
#dashboard-container {
    height: 100%;
}

#monitors-row, #status-row, #actions-row {
    height: auto;
    margin: 1 0;
    min-height: 3;
}

#monitors-row {
    height: 1fr;
}

#status-row {
    height: 1fr;
}

#actions-row {
    height: auto;
}

#identity-status, #api-status, #files-status {
    border: solid $border-primary;
    margin: 0 1;
    padding: 1;
    min-height: 5;
    height: 1fr;
}

/* System Monitor styling */
SystemMonitor {
    background: $bg-light;
    color: $text-primary;
    border: solid $border-primary;
    margin: 1;
    padding: 1;
}

/* Button styling */
Button {
    background: $bg-dark;
    color: $primary;
    border: solid $primary;
    text-style: bold;
}

Button:hover {
    background: $primary;
    color: $bg-dark;
}

Button.-primary {
    background: $primary;
    color: $bg-dark;
}

/* Input styling */
Input {
    background: $bg-dark;
    color: $text-primary;
    border: solid $border-primary;
}

Input:focus {
    border: solid $accent;
}

/* Table styling */
DataTable {
    background: $bg-dark;
    color: $text-primary;
    border: solid $border-primary;
}

DataTable > .datatable--header {
    background: $bg-medium;
    color: $primary;
    text-style: bold;
}

DataTable > .datatable--row {
    background: $bg-dark;
    color: $text-secondary;
}

DataTable > .datatable--row:hover {
    background: $bg-light;
}

/* Progress bar styling */
ProgressBar {
    background: $bg-dark;
    color: $primary;
    border: solid $border-primary;
}

/* Static text styling */
Static {
    color: $text-secondary;
}

Static.info {
    background: $accent;
    color: $bg-dark;
    text-style: bold;
}

Static.success {
    background: $success;
    color: $bg-dark;
    text-style: bold;
}

Static.warning {
    background: $warning;
    color: $bg-dark;
    text-style: bold;
}

Static.error {
    background: $error;
    color: $text-secondary;
    text-style: bold;
}

/* Containers */
Container {
}

Horizontal {
}

Vertical {
}

/* Scrollbars */
Scrollbar {
    background: $bg-medium;
    color: $primary;
}

Scrollbar:hover {
    background: $bg-light;
}

/* Loading indicators */
LoadingIndicator {
    color: $primary;
    background: $bg-dark;
}

/* Special cyberpunk effects */
.matrix-text {
    color: $primary;
    text-style: bold;
}

.neon-border {
    border: solid $accent;
    background: $bg-dark;
}

.replicant-amber {
    color: #ffb000;
    background: $bg-dark;
}

.blade-runner-green {
    color: #00ff41;
    background: #001100;
}

.art-deco-border {
    border: double $border-primary;
    background: $bg-medium;
}

/* Animation classes for future use */
.pulse {
    /* Will be used for pulsing effects */
}

.glow {
    /* Will be used for glow effects */
}
"""

    return base_colors + background_vars + common_styles


# Default theme with normal backgrounds
CYBERPUNK_THEME = get_cyberpunk_theme(transparent_background=False)
