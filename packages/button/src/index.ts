/**
 * @ownerswitchai/button — V0 physical kill button.
 * A press (USB keyboard button or local HTTP) becomes a signed POST /kill.
 */
export { createButtonDaemon } from "./daemon.js";
export type { ButtonDaemon, ButtonDaemonOptions, KillConfirmation } from "./daemon.js";

export { createHttpSource, createKeyboardSource, DEFAULT_HTTP_PORT } from "./input.js";
export type {
  HttpPressSource,
  HttpSourceOptions,
  KeyboardSourceOptions,
  KeyboardStdin,
  OnPress,
  PressListener,
  PressSource,
  Unsubscribe,
} from "./input.js";
