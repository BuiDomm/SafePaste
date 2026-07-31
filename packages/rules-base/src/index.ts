import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

export type DeclarativeRulePack = {
  manifest: {
    apiVersion: number;
    id: string;
    version: string;
    minEngineVersion: string;
    license: string;
    locales: string[];
  };
  rules: Array<Record<string, unknown>>;
};

export const baseRulePack = require("../rules.json") as DeclarativeRulePack;
