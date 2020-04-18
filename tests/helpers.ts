import { Pool } from "pg";

import {
    newModel,
    newEnforcer,

    Model,
    Enforcer,
    Assertion
} from "casbin";

import PostgresAdapter from "..";
import { CasbinRule } from "../lib/model";

export const connectionString = "postgresql://casbin:casbin@localhost:5432/casbin";
export const pool = new Pool({ connectionString });

//#region New Methods

export function buildModel(): Model {
    const m = newModel();
    m.loadModel(__dirname + "/assets/model.conf");

    return m;
}

export function buildAdapter(): Promise<PostgresAdapter> {
    return PostgresAdapter.newAdapter({ connectionString });
}

export async function buildEnforcer(): Promise<[Model, PostgresAdapter, Enforcer]> {
    const m = buildModel();
    const a = await buildAdapter();
    const e = await newEnforcer(m, a);

    return [m, a, e];
}

//#endregion

//#region Sample Data

export function getSamplePolicies(): CasbinRule[] {
    return require("./assets/policies.json");
}

export function getSampleRoles(): CasbinRule[] {
    return require("./assets/roles.json");
}

export function getSampleData(): CasbinRule[] {
    return getSamplePolicies().concat(getSampleRoles());
}

export async function importSampleData(): Promise<void> {
    const rules = getSampleData();

    const req: string[] = [];
    const values: string[] = [];

    let i = 1;
    for (const { ptype, rule } of rules) {
        req.push(`($${i++}, $${i++}::jsonb)`);
        values.push(ptype, JSON.stringify(rule));
    }

    await pool.query(
        "INSERT INTO casbin (ptype, rule) VALUES " + req.join(", "),
        values
    );
}

//#endregion

//#region DB Tests

export async function dbGetAll(): Promise<CasbinRule[]> {
    const { rows } = await pool.query("SELECT ptype, rule FROM casbin");
    return rows;
}

export function getRulesFromModel(m: Model, sec: string): CasbinRule[] {
    const rules: CasbinRule[] = [];

    let astMap = m.model.get(sec) as Map<string, Assertion>;
    for (const [ptype, ast] of astMap) {
        for (const rule of ast.policy) {
            rules.push({ ptype, rule });
        }
    }

    return rules;
}

//#endregion

//#region Clean Methods

export async function cleanAdapter(a: PostgresAdapter): Promise<void> {
    await a.close();
}

export async function cleanDB(): Promise<void> {
    await pool.query("DELETE FROM casbin");
}

export async function cleanEnv(): Promise<void> {
    await pool.end();
}

//#endregion
