"""
Cyberpunk Theme for dCypher TUI
Inspired by @repligate, Blade Runner, and cipherpunk aesthetics
"""

CYBERPUNK_THEME = """
/* Global Variables - Cyberpunk Color Palette */
$primary: #00ff41;        /* Matrix green */
$secondary: #ff6b35;      /* Neon orange */
$accent: #00d4ff;         /* Cyan blue */
$warning: #ffff00;        /* Electric yellow */
$error: #ff073a;          /* Neon red */
$success: #39ff14;        /* Bright green */

$bg-dark: #0a0a0a;        /* Deep black */
$bg-medium: #1a1a1a;      /* Dark gray */
$bg-light: #2a2a2a;       /* Medium gray */
$text-primary: #00ff41;   /* Matrix green text */
$text-secondary: #ffffff; /* White text */
$text-dim: #888888;       /* Dim gray */

$border-primary: #00ff41; /* Matrix green border */
$border-secondary: #ff6b35; /* Orange border */

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
    color: $text-primary;
    border: solid $border-primary;
}

Footer .footer--key {
    color: $accent;
    text-style: bold;
}

Footer .footer--description {
    color: $text-secondary;
}

/* Main container */
#main-container {
    background: $bg-dark;
    border: solid $border-primary;
    margin: 1;
    padding: 1;
}

/* ASCII Banner */
ASCIIBanner {
    height: 8;
    background: $bg-dark;
    color: $primary;
    text-align: center;
    text-style: bold;
    border: solid $border-secondary;
    margin-bottom: 1;
}

/* Tabbed Content - Art Deco inspired */
TabbedContent {
    background: $bg-dark;
    border: solid $border-primary;
}

TabbedContent > Tabs {
    background: $bg-medium;
    border-bottom: solid $border-primary;
}

TabbedContent > Tabs > Tab {
    background: $bg-medium;
    color: $text-dim;
    border: none;
    margin-right: 1;
    padding: 0 2;
}

TabbedContent > Tabs > Tab:hover {
    background: $bg-light;
    color: $text-primary;
}

TabbedContent > Tabs > Tab.-active {
    background: $bg-dark;
    color: $primary;
    border: solid $border-primary;
    border-bottom: none;
    text-style: bold;
}

TabbedContent > ContentSwitcher {
    background: $bg-dark;
    padding: 1;
}

/* System Monitor Widget */
SystemMonitor {
    height: 10;
    background: $bg-medium;
    border: solid $border-primary;
    margin: 1;
    padding: 1;
}

SystemMonitor .title {
    color: $primary;
    text-style: bold;
    text-align: center;
}

SystemMonitor .metric {
    color: $text-secondary;
}

SystemMonitor .value {
    color: $accent;
    text-style: bold;
}

/* Data Tables */
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

DataTable > .datatable--cursor {
    background: $bg-light;
    color: $text-secondary;
}

/* Input widgets */
Input {
    background: $bg-medium;
    color: $text-primary;
    border: solid $border-primary;
}

Input:focus {
    border: solid $accent;
}

/* Buttons */
Button {
    background: $bg-medium;
    color: $text-primary;
    border: solid $border-primary;
    text-style: bold;
}

Button:hover {
    background: $bg-light;
    color: $primary;
    border: solid $primary;
}

Button.-primary {
    background: $primary;
    color: $bg-dark;
    border: solid $primary;
}

Button.-primary:hover {
    background: $success;
    border: solid $success;
}

Button.-danger {
    background: $error;
    color: $text-secondary;
    border: solid $error;
}

Button.-danger:hover {
    background: #cc0000;
    border: solid #cc0000;
}

/* Progress bars */
ProgressBar {
    background: $bg-medium;
    border: solid $border-primary;
}

ProgressBar > .bar--bar {
    background: $primary;
}

ProgressBar > .bar--percentage {
    color: $text-secondary;
    text-style: bold;
}

/* Log display */
RichLog {
    background: $bg-dark;
    color: $text-primary;
    border: solid $border-primary;
    scrollbar-background: $bg-medium;
    scrollbar-color: $primary;
}

/* Tree widget */
Tree {
    background: $bg-dark;
    color: $text-primary;
    border: solid $border-primary;
}

Tree > .tree--guides {
    color: $text-dim;
}

Tree > .tree--guides-selected {
    color: $primary;
}

/* Static text containers */
Static {
    background: $bg-dark;
    color: $text-primary;
}

Static.panel {
    background: $bg-medium;
    border: solid $border-primary;
    padding: 1;
    margin: 1;
}

Static.highlight {
    background: $bg-light;
    color: $primary;
    text-style: bold;
}

Static.error {
    background: $error;
    color: $text-secondary;
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

/* Containers */
Container {
    background: $bg-dark;
}

Horizontal {
    background: $bg-dark;
}

Vertical {
    background: $bg-dark;
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