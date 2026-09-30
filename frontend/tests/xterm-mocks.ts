/**
 * A stand-in for xterm.js (jsdom has no canvas/layout). Test files mount it with:
 *
 *   vi.mock("@xterm/xterm", async () => ({ Terminal: (await import("./xterm-mocks")).FakeTerminal }));
 *   vi.mock("@xterm/addon-fit", async () => ({ FitAddon: (await import("./xterm-mocks")).FakeFit }));
 */
type Cb<T> = (value: T) => void;

export class FakeTerminal {
  static instances: FakeTerminal[] = [];
  cols = 80;
  rows = 24;
  written: string[] = [];
  disposed = false;
  focused = false;
  dataListeners: Cb<string>[] = [];
  resizeListeners: Cb<{ cols: number; rows: number }>[] = [];
  element: HTMLElement | null = null;
  constructor(public options: Record<string, unknown> = {}) {
    FakeTerminal.instances.push(this);
  }
  loadAddon() {}
  open(el: HTMLElement) {
    this.element = el;
  }
  write(data: Uint8Array | string) {
    this.written.push(typeof data === "string" ? data : new TextDecoder().decode(data));
  }
  focus() {
    this.focused = true;
  }
  onData(cb: Cb<string>) {
    this.dataListeners.push(cb);
    return { dispose: () => (this.dataListeners = this.dataListeners.filter((x) => x !== cb)) };
  }
  onResize(cb: Cb<{ cols: number; rows: number }>) {
    this.resizeListeners.push(cb);
    return { dispose: () => (this.resizeListeners = this.resizeListeners.filter((x) => x !== cb)) };
  }
  dispose() {
    this.disposed = true;
  }
  type(text: string) {
    this.dataListeners.forEach((cb) => cb(text));
  }
  resize(cols: number, rows: number) {
    this.cols = cols;
    this.rows = rows;
    this.resizeListeners.forEach((cb) => cb({ cols, rows }));
  }
  get text() {
    return this.written.join("");
  }
}

export class FakeFit {
  fit() {}
}
