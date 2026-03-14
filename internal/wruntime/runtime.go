package wruntime

import (
	"context"
	"runtime"

	"github.com/wailsapp/wails/v3/pkg/application"
)

const (
	InfoDialog = iota
	QuestionDialog
	WarningDialog
	ErrorDialog
)

var GOOS = runtime.GOOS

type FileFilter = application.FileFilter

type OpenDialogOptions struct {
	Title   string
	Filters []FileFilter
}

type SaveDialogOptions struct {
	Title           string
	DefaultFilename string
}

type MessageDialogOptions struct {
	Type          int
	Title         string
	Message       string
	DefaultButton string
	CancelButton  string
	Buttons       []string
}

func app() *application.App {
	return application.Get()
}

func currentWindow() application.Window {
	if app := app(); app != nil {
		if window := app.Window.Current(); window != nil {
			return window
		}
		windows := app.Window.GetAll()
		if len(windows) > 0 {
			return windows[0]
		}
	}
	return nil
}

func EventsEmit(_ context.Context, name string, data ...interface{}) {
	applicationEvent := &application.CustomEvent{
		Name: name,
	}
	switch len(data) {
	case 0:
	case 1:
		applicationEvent.Data = data[0]
	default:
		applicationEvent.Data = data
	}
	if app := app(); app != nil {
		app.Event.EmitEvent(applicationEvent)
	}
}

func BrowserOpenURL(_ context.Context, url string) error {
	if app := app(); app != nil {
		return app.Browser.OpenURL(url)
	}
	return nil
}

func MessageDialog(_ context.Context, options MessageDialogOptions) (string, error) {
	app := app()
	if app == nil {
		return "", nil
	}

	var dialog *application.MessageDialog
	switch options.Type {
	case QuestionDialog:
		dialog = app.Dialog.Question()
	case WarningDialog:
		dialog = app.Dialog.Warning()
	case ErrorDialog:
		dialog = app.Dialog.Error()
	default:
		dialog = app.Dialog.Info()
	}

	if options.Title != "" {
		dialog.SetTitle(options.Title)
	}
	if options.Message != "" {
		dialog.SetMessage(options.Message)
	}
	if window := currentWindow(); window != nil {
		dialog.AttachToWindow(window)
	}

	result := make(chan string, 1)
	addButton := func(label string, selected bool) {
		button := dialog.AddButton(label)
		if selected {
			button.OnClick(func() {
				select {
				case result <- label:
				default:
				}
			})
		}
		if label == options.DefaultButton {
			dialog.SetDefaultButton(button)
		}
		if label == options.CancelButton {
			dialog.SetCancelButton(button)
		}
	}

	if len(options.Buttons) == 0 {
		defaultLabel := options.DefaultButton
		if defaultLabel == "" {
			defaultLabel = "OK"
		}
		addButton(defaultLabel, true)
	} else {
		for _, label := range options.Buttons {
			addButton(label, true)
		}
	}

	dialog.Show()
	select {
	case selected := <-result:
		return selected, nil
	default:
		return "", nil
	}
}

func OpenFileDialog(_ context.Context, options OpenDialogOptions) (string, error) {
	app := app()
	if app == nil {
		return "", nil
	}
	dialog := app.Dialog.OpenFileWithOptions(&application.OpenFileDialogOptions{
		Title:   options.Title,
		Filters: options.Filters,
		Window:  currentWindow(),
	})
	return dialog.PromptForSingleSelection()
}

func OpenDirectoryDialog(_ context.Context, options OpenDialogOptions) (string, error) {
	app := app()
	if app == nil {
		return "", nil
	}
	dialog := app.Dialog.OpenFileWithOptions(&application.OpenFileDialogOptions{
		Title:                options.Title,
		CanChooseDirectories: true,
		CanChooseFiles:       false,
		Window:               currentWindow(),
	})
	return dialog.PromptForSingleSelection()
}

func SaveFileDialog(_ context.Context, options SaveDialogOptions) (string, error) {
	app := app()
	if app == nil {
		return "", nil
	}
	dialog := app.Dialog.SaveFileWithOptions(&application.SaveFileDialogOptions{
		Title:    options.Title,
		Filename: options.DefaultFilename,
		Window:   currentWindow(),
	})
	return dialog.PromptForSingleSelection()
}
