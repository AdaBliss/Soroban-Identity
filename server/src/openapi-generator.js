import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { V1_ROUTES } from "./routes/v1.js";

const HERE = dirname(fileURLToPath(import.meta.url));
export const BASE_SPEC_PATH = resolve(HERE, "../openapi.json");
export const GENERATED_SPEC_PATH = resolve(HERE, "../openapi.generated.json");

const METHOD_OPERATIONS = {
  GET: { tag: "read", response: "200", description: "Successful response" },
  POST: { tag: "write", response: "201", description: "Resource created or action accepted" },
  PATCH: { tag: "write", response: "200", description: "Resource updated" },
  DELETE: { tag: "write", response: "204", description: "Resource deleted" },
};

export function toOpenApiPath(path) {
  return String(path).replace(/:([A-Za-z0-9_]+)/g, "{$1}");
}

export function collectPathParameters(path) {
  const names = String(path).match(/:([A-Za-z0-9_]+)/g) ?? [];
  return names.map((token) => {
    const name = token.slice(1);
    return {
      name,
      in: "path",
      required: true,
      schema: { type: "string" },
      description: `${name} identifier`,
    };
  });
}

export function tagForRoute(name, path) {
  const segment = String(path).split("/").filter(Boolean)[0] ?? "system";
  if (name.startsWith("cache")) return "system";
  if (segment === "admin") return "admin";
  if (segment === "credentials" || segment === "batch") return "credentials";
  if (segment === "webhooks") return "webhooks";
  return segment;
}

export function humanizeRouteName(name) {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/^./, (character) => character.toUpperCase());
}

export function generateOpenApiSpec(baseSpec, routes = V1_ROUTES) {
  const spec = structuredClone(baseSpec);
  spec.paths = spec.paths ?? {};
  spec.components = spec.components ?? {};
  spec.components.securitySchemes = spec.components.securitySchemes ?? {};
  spec.tags = Array.isArray(spec.tags) ? [...spec.tags] : [];

  const addedTags = new Set(spec.tags.map((tag) => tag.name));
  const generated = [];

  for (const [name, descriptor] of Object.entries(routes)) {
    if (!descriptor?.method || !descriptor?.path) continue;
    const method = String(descriptor.method).toLowerCase();
    const path = toOpenApiPath(descriptor.path);
    const operation = METHOD_OPERATIONS[descriptor.method];
    if (!operation) continue;

    spec.paths[path] = spec.paths[path] ?? {};
    if (spec.paths[path][method]) continue;

    const tag = tagForRoute(name, descriptor.path);
    if (!addedTags.has(tag)) {
      spec.tags.push({ name: tag, description: `${tag} endpoints` });
      addedTags.add(tag);
    }

    const parameters = collectPathParameters(descriptor.path);
    spec.paths[path][method] = {
      tags: [tag],
      summary: humanizeRouteName(name),
      description: `Generated from the ${name} route descriptor.`,
      operationId: name,
      ...(descriptor.read ? {} : { security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }] }),
      ...(parameters.length ? { parameters } : {}),
      responses: {
        [operation.response]: { description: operation.description },
        "400": { description: "Invalid request" },
        "401": { description: "Authentication required" },
        "500": { description: "Internal server error" },
      },
    };
    generated.push({ name, method, path });
  }

  spec["x-generated-routes"] = generated;
  spec["x-generator"] = "server/src/openapi-generator.js";
  return spec;
}

export async function buildGeneratedSpec() {
  const baseSpec = JSON.parse(await readFile(BASE_SPEC_PATH, "utf8"));
  return generateOpenApiSpec(baseSpec);
}

export async function writeGeneratedSpec() {
  const spec = await buildGeneratedSpec();
  await writeFile(GENERATED_SPEC_PATH, `${JSON.stringify(spec, null, 2)}\n`, "utf8");
  return spec;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const spec = await writeGeneratedSpec();
  process.stdout.write(
    `Generated ${GENERATED_SPEC_PATH} with ${Object.keys(spec.paths).length} paths\n`,
  );
}
