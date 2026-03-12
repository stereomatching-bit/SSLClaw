package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"sslclaw/internal/ui"
)

func main() {
	a := app.NewWithID("com.sslclaw.app")
	a.Settings().SetTheme(ui.NewSSLClawTheme(true)) // dark mode by default

	win := a.NewWindow("SSLClaw — SSL/TLS Scanner & KeyStore Manager")
	win.Resize(fyne.NewSize(1280, 800))
	win.CenterOnScreen()

	// Theme toggle
	isDark := true
	themeBtn := widget.NewButton("🌙 Dark", nil)
	themeBtn.OnTapped = func() {
		isDark = !isDark
		a.Settings().SetTheme(ui.NewSSLClawTheme(isDark))
		if isDark {
			themeBtn.SetText("🌙 Dark")
		} else {
			themeBtn.SetText("☀️ Light")
		}
	}

	// Title bar
	titleLabel := widget.NewRichTextFromMarkdown("# 🔒 SSLClaw")
	versionLabel := widget.NewLabel("v1.0.0")
	versionLabel.TextStyle = fyne.TextStyle{Italic: true}

	titleBar := container.NewHBox(
		titleLabel,
		versionLabel,
		layout.NewSpacer(),
		themeBtn,
	)

	// Content area
	contentArea := container.NewMax(ui.ScannerTab(win))

	// Navigation items
	type navItem struct {
		name string
		icon string
		fn   func() fyne.CanvasObject
	}

	navItems := []navItem{
		{"SSL/TLS Scanner", "🔍", func() fyne.CanvasObject { return ui.ScannerTab(win) }},
		{"KeyStore Manager", "🔑", func() fyne.CanvasObject { return ui.KeyStoreTab(win) }},
	}

	// Sidebar
	sideList := widget.NewList(
		func() int {
			return len(navItems)
		},
		func() fyne.CanvasObject {
			return container.NewHBox(widget.NewLabel(""), widget.NewLabel(""))
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			item := navItems[id]
			box := obj.(*fyne.Container)
			box.Objects[0].(*widget.Label).SetText(item.icon)
			box.Objects[1].(*widget.Label).SetText(item.name)
		},
	)

	sideList.OnSelected = func(id widget.ListItemID) {
		contentArea.Objects = []fyne.CanvasObject{navItems[id].fn()}
		contentArea.Refresh()
	}
	sideList.Select(0) // Default to scanner

	sidebar := container.NewBorder(
		nil, nil, nil, nil,
		sideList,
	)

	// Main layout using HSplit for resizable sidebar
	split := container.NewHSplit(sidebar, contentArea)
	split.Offset = 0.2 // 20% sidebar width

	mainContent := container.NewBorder(
		container.NewVBox(titleBar, widget.NewSeparator()),
		nil, nil, nil,
		split,
	)

	win.SetContent(mainContent)
	win.ShowAndRun()
}
