/**
 * Characterizes the ERROR paths for credential values (#5646). The `get-env`
 * masking contract is pinned on its success path (tools.test.ts); these cases
 * pin that a planted credential-like value reaches none of the other faces a
 * tool has: a validation error and the gzip tool's private-address refusal,
 * with the opt-in off and, for the refusal, also with it on. Every reading of
 * the masking rule treats `OPENAI_API_KEY` as credential-like, so its value is
 * the one that must not surface anywhere but `get-env`'s own output.
 *
 * No leak was found on any of these paths; this file pins that. It is a
 * characterization, so it passes on unmodified main.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { INCLUDE_SECRETS_VAR } from "../tools/get-env.js";
import { connect, contentOf, textOf, type Session } from "./harness.js";

const SECRET = "sk-pla...9c4d";

// `gzip-file-as-resource` reads this once, when its module is evaluated, so a
// developer's shell must not be able to opt the refusal away.
vi.hoisted(() => {
  vi.stubEnv("GZIP_ALLOW_PRIVATE_IPS", undefined);
});

let session: Session | undefined;

afterEach(async () => {
  await session?.close();
  session = undefined;
  vi.unstubAllEnvs();
});

/** Connects a session with the planted credential and the opt-in as given. */
async function open(includeSecrets?: string): Promise<Session> {
  vi.stubEnv("OPENAI_API_KEY", SECRET);
  vi.stubEnv(INCLUDE_SECRETS_VAR, includeSecrets);
  session = await connect();
  return session;
}

describe("error paths carry no credential value (#5646)", () => {
  it.each([
    ["get-structured-content", { location: "Paris" }],
    ["get-annotated-message", { messageType: "info" }],
  ])(
    "returns a %s validation error without the value, with masking on",
    async (name, args) => {
      const { client } = await open(undefined);
      const result = await client.callTool({ name, arguments: args });
      expect(result.isError).toBe(true);
      expect(textOf(contentOf(result)[0])).toContain(name);
      expect(JSON.stringify(result)).not.toContain(SECRET);
    },
  );

  it("refuses a private address without the value, with masking on", async () => {
    const { client } = await open(undefined);
    const url = "http://127.0.0.1:9/secret";
    const result = await client.callTool({
      name: "gzip-file-as-resource",
      arguments: { name: "x.gz", data: url },
    });
    expect(result.isError).toBe(true);
    expect(textOf(contentOf(result)[0])).toContain(
      "which is not a public address",
    );
    expect(JSON.stringify(result)).not.toContain(SECRET);
  });

  it("refuses a private address without the value, with the opt-in on", async () => {
    const { client } = await open("1");
    // The opt-in is live in this session: it does open get-env's own output.
    const env = await client.callTool({ name: "get-env", arguments: {} });
    expect(JSON.parse(textOf(contentOf(env)[0])).OPENAI_API_KEY).toBe(SECRET);
    const result = await client.callTool({
      name: "gzip-file-as-resource",
      arguments: { name: "x.gz", data: "http://127.0.0.1:9/secret" },
    });
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result)).not.toContain(SECRET);
  });
});
