import { shell } from "electron";

/** Legacy helper retained for callers: development also uses the system browser. */
export async function openDevelopmentLoginWindow(options: { authorizeUrl: string }): Promise<string> {
  const url = new URL(options.authorizeUrl);
  if (!/^https?:$/.test(url.protocol) || url.username || url.password) throw new Error("Invalid development OAuth URL.");
  await shell.openExternal(url.toString());
  return options.authorizeUrl;
}
