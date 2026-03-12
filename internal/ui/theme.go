package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// SSLClawTheme is a custom Fyne theme for SSLClaw
type SSLClawTheme struct {
	dark bool
}

// NewSSLClawTheme creates a new theme
func NewSSLClawTheme(dark bool) *SSLClawTheme {
	return &SSLClawTheme{dark: dark}
}

// Color returns the named color for the theme
func (t *SSLClawTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	if t.dark {
		variant = theme.VariantDark
	} else {
		variant = theme.VariantLight
	}

	switch name {
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 0, G: 150, B: 255, A: 255} // Electric blue
	case theme.ColorNameBackground:
		if t.dark {
			return color.NRGBA{R: 18, G: 18, B: 24, A: 255}
		}
		return color.NRGBA{R: 245, G: 247, B: 250, A: 255}
	case theme.ColorNameButton:
		return color.NRGBA{R: 0, G: 150, B: 255, A: 255}
	case theme.ColorNameDisabled:
		return color.NRGBA{R: 100, G: 100, B: 100, A: 255}
	case theme.ColorNameError:
		return color.NRGBA{R: 255, G: 59, B: 48, A: 255} // Red
	case theme.ColorNameSuccess:
		return color.NRGBA{R: 48, G: 209, B: 88, A: 255} // Green
	case theme.ColorNameWarning:
		return color.NRGBA{R: 255, G: 159, B: 10, A: 255} // Amber
	}

	return theme.DefaultTheme().Color(name, variant)
}

// Font returns the named font for the theme
func (t *SSLClawTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

// Icon returns the named icon for the theme
func (t *SSLClawTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

// Size returns the named size for the theme
func (t *SSLClawTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 6
	case theme.SizeNameInnerPadding:
		return 4
	case theme.SizeNameText:
		return 14
	case theme.SizeNameSubHeadingText:
		return 16
	case theme.SizeNameHeadingText:
		return 20
	}
	return theme.DefaultTheme().Size(name)
}

// Security-aware colors for the UI
var (
	ColorSecure     = color.NRGBA{R: 48, G: 209, B: 88, A: 255}  // Green
	ColorAcceptable = color.NRGBA{R: 0, G: 150, B: 255, A: 255}  // Blue
	ColorWeak       = color.NRGBA{R: 255, G: 159, B: 10, A: 255} // Amber
	ColorInsecure   = color.NRGBA{R: 255, G: 59, B: 48, A: 255}  // Red
	ColorNeutral    = color.NRGBA{R: 142, G: 142, B: 147, A: 255} // Gray
)
