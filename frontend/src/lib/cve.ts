/** CVE identifier helpers shared by server and client code. */

// [0-9], not \d: keep this strictly ASCII, mirroring the backend validation.
const CVE_ID_RE = /^CVE-[0-9]{4}-[0-9]{4,19}$/;

export const MAX_QUERY_LENGTH = 100;

export function normalizeCveId(value: string): string | null {
  const candidate = value.trim().toUpperCase();
  return CVE_ID_RE.test(candidate) ? candidate : null;
}

/** Parse a raw route segment into a canonical CVE ID; never throws on malformed escapes. */
export function parseCveIdParam(raw: string): string | null {
  try {
    return normalizeCveId(decodeURIComponent(raw));
  } catch {
    return null;
  }
}

/** Trim, drop control characters and cap the length of a user-supplied search query. */
export function sanitizeQuery(value: string | undefined): string {
  const cleaned = (value ?? "").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, "");
  return cleaned.trim().slice(0, MAX_QUERY_LENGTH);
}

export interface ExampleCve {
  id: string;
  name: string;
  summary: string;
}

/** Well-known CVEs offered as starting points. Only names; no vulnerability details are asserted. */
export const EXAMPLE_CVES: ExampleCve[] = [
  { id: "CVE-2021-44228", name: "Log4Shell", summary: "Apache Log4j2 JNDI lookup" },
  { id: "CVE-2014-0160", name: "Heartbleed", summary: "OpenSSL heartbeat extension" },
  { id: "CVE-2014-6271", name: "Shellshock", summary: "GNU Bash environment handling" },
  { id: "CVE-2017-0144", name: "EternalBlue", summary: "Microsoft SMBv1 server" },
  { id: "CVE-2022-22965", name: "Spring4Shell", summary: "Spring Framework data binding" },
];

const CWE_RE = /^CWE-([0-9]{1,6})$/;

/** Link to the MITRE CWE definition, only for well-formed CWE identifiers. */
export function cweUrl(cwe: string): string | null {
  const match = CWE_RE.exec(cwe);
  return match ? `https://cwe.mitre.org/data/definitions/${match[1]}.html` : null;
}
