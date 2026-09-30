/**
 * Only absolute http(s) URLs may be rendered as links. Anything else (javascript:, data:,
 * file:, relative or malformed values) is treated as unsafe: external content is untrusted.
 */
export function safeHttpUrl(value: string | null | undefined): string | null {
  if (!value || /[\u0000- \u007f]/.test(value)) return null;
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" ? url.toString() : null;
  } catch {
    return null;
  }
}
