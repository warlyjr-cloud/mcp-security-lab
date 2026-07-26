const SAFE_ENV_KEYS = [
  "COMSPEC",
  "OS",
  "PATH",
  "PATHEXT",
  "SYSTEMDRIVE",
  "SYSTEMROOT",
  "TEMP",
  "TMP",
  "WINDIR",
  "HOME",
  "LANG",
  "LC_ALL",
  "SHELL",
] as const;

const NON_OVERRIDABLE_ENV_KEYS = [
  "DYLD_INSERT_LIBRARIES",
  "DYLD_LIBRARY_PATH",
  "LD_LIBRARY_PATH",
  "LD_PRELOAD",
  "MCP_SECURITY_LAB",
  "NODE_OPTIONS",
  "NODE_PATH",
] as const;

export const RESERVED_ENV_KEYS: ReadonlySet<string> = new Set<string>([
  ...SAFE_ENV_KEYS,
  ...NON_OVERRIDABLE_ENV_KEYS,
]);

const SENSITIVE_FLAG_PATTERN =
  /^--?(?:api[-_]?key|authorization|credential|password|secret|token)$/i;
const SENSITIVE_ASSIGNMENT_PATTERN =
  /^((?:--?)?(?:api[-_]?key|authorization|credential|password|secret|token)=).+$/i;
const SENSITIVE_ENV_ASSIGNMENT_PATTERN =
  /^([A-Z0-9_]*(?:API_KEY|AUTHORIZATION|CREDENTIAL|PASSWORD|SECRET|TOKEN)=).+$/i;
const URL_CREDENTIAL_PATTERN = /^([a-z][a-z0-9+.-]*:\/\/)[^/@\s]+@/i;

export function createSanitizedEnvironment(
  source: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
  const environment: Record<string, string> = {};

  for (const key of SAFE_ENV_KEYS) {
    const value = source[key];
    if (value !== undefined) {
      environment[key] = value;
    }
  }

  environment.MCP_SECURITY_LAB = "1";
  return environment;
}

const SENSITIVE_QUERY_KEY_PATTERN =
  /^(api[-_]?key|access[-_]?token|auth|authorization|credential|key|password|secret|token)$/i;

/**
 * Remove credentials from a URL before it enters a report: strip any userinfo
 * (`user:pass@`) and redact the value of sensitive query parameters. Falls back
 * to a coarse regex when the string is not a parseable URL.
 */
export function redactUrl(rawUrl: string): string {
  try {
    const url = new URL(rawUrl);
    if (url.username !== "" || url.password !== "") {
      url.username = "[REDACTED]";
      url.password = "";
    }
    for (const key of [...url.searchParams.keys()]) {
      if (SENSITIVE_QUERY_KEY_PATTERN.test(key)) {
        url.searchParams.set(key, "[REDACTED]");
      }
    }
    // URL percent-encodes the brackets of our sentinel; restore it for readability.
    return url.toString().replace(/%5BREDACTED%5D/g, "[REDACTED]");
  } catch {
    return rawUrl.replace(URL_CREDENTIAL_PATTERN, "$1[REDACTED]@");
  }
}

export function redactArguments(args: string[]): string[] {
  const redacted: string[] = [];
  let redactNext = false;

  for (const argument of args) {
    if (redactNext) {
      redacted.push("[REDACTED]");
      redactNext = false;
      continue;
    }
    if (SENSITIVE_FLAG_PATTERN.test(argument)) {
      redacted.push(argument);
      redactNext = true;
      continue;
    }
    if (SENSITIVE_ASSIGNMENT_PATTERN.test(argument)) {
      redacted.push(argument.replace(SENSITIVE_ASSIGNMENT_PATTERN, "$1[REDACTED]"));
      continue;
    }
    if (SENSITIVE_ENV_ASSIGNMENT_PATTERN.test(argument)) {
      redacted.push(argument.replace(SENSITIVE_ENV_ASSIGNMENT_PATTERN, "$1[REDACTED]"));
      continue;
    }
    if (URL_CREDENTIAL_PATTERN.test(argument)) {
      redacted.push(argument.replace(URL_CREDENTIAL_PATTERN, "$1[REDACTED]@"));
      continue;
    }
    redacted.push(argument);
  }

  return redacted;
}
