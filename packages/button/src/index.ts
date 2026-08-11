/**
 * @ownerswitchai/button — V0 physical kill button.
 * A press (USB keyboard button, local HTTP, or a serial e-stop) becomes a
 * signed POST /kill.
 */
export { createButtonDaemon } from "./daemon.js";
export type { ButtonDaemon, ButtonDaemonOptions, KillConfirmation } from "./daemon.js";

export {
  createHttpSource,
  createKeyboardSource,
  createSerialSource,
  DEFAULT_HTTP_PORT,
  DEFAULT_SERIAL_TRIGGER,
} from "./input.js";
export type {
  HttpPressSource,
  HttpSourceOptions,
  KeyboardSourceOptions,
  KeyboardStdin,
  OnPress,
  PressListener,
  PressSource,
  SerialPortStream,
  SerialSourceOptions,
  Unsubscribe,
} from "./input.js";
