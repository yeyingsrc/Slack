package main

import (
	"embed"
	core "slack-wails/core/tools"
	"slack-wails/services"

	rt "runtime"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	svcApp := services.NewApp()
	file := services.NewFile()
	db := services.NewDatabase()
	exp := services.NewExp()
	windowSize := db.SelectWindowsSize()

	app := application.New(application.Options{
		Name: "Slack",
		Assets: application.AssetOptions{
			Handler: application.BundledAssetFileServer(assets),
		},
		Services: []application.Service{
			application.NewService(svcApp),
			application.NewService(file),
			application.NewService(db),
			application.NewService(exp),
			application.NewService(&core.Tools{}),
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: true,
		},
		Windows: application.WindowsOptions{
			WebviewBrowserPath: "", // 可以让windows使用默认浏览器打开链接
		},
	})

	window := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:             "main",
		Title:            "Slack",
		Width:            windowSize.Width,
		Height:           windowSize.Height,
		MinWidth:         1280,
		MinHeight:        768,
		EnableFileDrop:   true,
		BackgroundColour: application.NewRGB(255, 255, 255),
		Frameless:        rt.GOOS != "darwin", // 屏蔽windows/linux原生标题栏
		Mac: application.MacWindow{
			TitleBar: application.MacTitleBar{
				AppearsTransparent: true,
				Hide:               false,
				HideTitle:          true,
				FullSizeContent:    true,
			},
			InvisibleTitleBarHeight: 35,
		},
	})
	window.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		if svcApp.BeforeClose(app.Context()) {
			e.Cancel()
		}
	})
	window.OnWindowEvent(events.Common.WindowFilesDropped, func(event *application.WindowEvent) {
		files := event.Context().DroppedFiles()
		details := event.Context().DropTargetDetails()
		app.Event.Emit("launcher:files-dropped", map[string]any{
			"files":   files,
			"details": details,
		})
	})

	if err := app.Run(); err != nil {
		println("Error:", err.Error())
	}
}
