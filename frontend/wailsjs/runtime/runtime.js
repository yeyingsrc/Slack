import { Application, Browser, Clipboard, Events, Window as CurrentWindow } from '@wailsio/runtime';

let fileDropCleanup = null;

function buildFileDropPayload(filenames, x, y) {
  const element = document.elementFromPoint(x, y);
  const dropTarget = element?.closest?.('[data-file-drop-target]');
  const elementDetails = dropTarget
    ? {
        id: dropTarget.id,
        classList: Array.from(dropTarget.classList),
        attributes: Array.from(dropTarget.attributes).reduce((acc, attr) => {
          acc[attr.name] = attr.value;
          return acc;
        }, {}),
      }
    : null;

  return {
    filenames: Array.isArray(filenames) ? filenames : [],
    x,
    y,
    elementDetails,
  };
}

export function EventsOn(eventName, callback) {
  return Events.On(eventName, callback);
}

export function EventsOff(eventName, ...additionalEventNames) {
  if (!eventName) {
    Events.OffAll();
    return;
  }
  Events.Off(eventName, ...additionalEventNames);
}

export function BrowserOpenURL(url) {
  return Browser.OpenURL(url);
}

export function ClipboardSetText(text) {
  return Clipboard.SetText(text);
}

export function WindowReload() {
  if (typeof CurrentWindow.ForceReload === 'function') {
    return CurrentWindow.ForceReload();
  }
  if (typeof CurrentWindow.Reload === 'function') {
    return CurrentWindow.Reload().catch(() => window.location.reload());
  }
  window.location.reload();
}

export function WindowToggleMaximise() {
  return CurrentWindow.ToggleMaximise();
}

export function WindowZoom() {
  return CurrentWindow.Zoom();
}

export function WindowMinimise() {
  return CurrentWindow.Minimise();
}

export function WindowGetSize() {
  return CurrentWindow.Size();
}

export function WindowIsMaximised() {
  return CurrentWindow.IsMaximised();
}

export function Quit() {
  return Application.Quit();
}

export function OnFileDrop(callback) {
  if (fileDropCleanup) {
    fileDropCleanup();
  }
  const originalHandlePlatformFileDrop = window?._wails?.handlePlatformFileDrop;
  if (typeof originalHandlePlatformFileDrop === 'function') {
    window._wails.handlePlatformFileDrop = function handlePlatformFileDropProxy(filenames, x, y) {
      const payload = buildFileDropPayload(filenames, x, y);
      callback(
        payload.x ?? 0,
        payload.y ?? 0,
        payload.filenames,
        payload.elementDetails,
        payload,
      );
      return originalHandlePlatformFileDrop.call(this, filenames, x, y);
    };
    fileDropCleanup = () => {
      if (window?._wails) {
        window._wails.handlePlatformFileDrop = originalHandlePlatformFileDrop;
      }
    };
    return fileDropCleanup;
  }

  fileDropCleanup = Events.On('common:WindowFilesDropped', (event) => {
    const payload = event?.data || {};
    const paths = Array.isArray(payload.filenames)
      ? payload.filenames
      : Array.isArray(payload.files)
        ? payload.files
        : [];
    callback(
      payload.x ?? 0,
      payload.y ?? 0,
      paths,
      payload.elementDetails || null,
      payload,
    );
  });
  return fileDropCleanup;
}

export function OnFileDropOff() {
  if (fileDropCleanup) {
    fileDropCleanup();
    fileDropCleanup = null;
  }
}
