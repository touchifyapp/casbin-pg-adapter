import * as path from "path";

import { Pool } from "pg";
import migrate from "node-pg-migrate";

import {
    CasbinRule,

    CasbinFilter,
    CasbinRuleFilter,

    PostgresAdapaterOptions
} from "./model";

export class CasbinRepository {
    private readonly options: PostgresAdapaterOptions;
    private readonly db: Pool;

    public constructor(options: PostgresAdapaterOptions) {
        this.options = options;
        this.db = new Pool(options);
    }

    public async getAllPolicies(): Promise<CasbinRule[]> {
        const { rows } = await this.db.query("SELECT ptype, rule FROM casbin");
        return rows;
    }

    public async getFilteredPolicies(filter: CasbinFilter): Promise<CasbinRule[]> {
        const [where, values] = buildWhereClause(filter);

        const { rows } = await this.db.query("SELECT ptype, rule FROM casbin" + where, values);
        return rows;
    }

    public async insertPolicy(ptype: string, rule: string[]): Promise<void> {
        await this.db.query(
            "INSERT INTO casbin (ptype, rule) VALUES ($1, $2::jsonb)",
            [ptype, JSON.stringify(rule)]
        );
    }

    public async insertPolicies(rules: CasbinRule[]): Promise<void> {
        const req: string[] = [];
        const values: string[] = [];

        let i = 1;
        for (const { ptype, rule } of rules) {
            req.push(`($${i++}, $${i++}::jsonb)`);
            values.push(ptype, JSON.stringify(rule));
        }

        await this.db.query(
            "INSERT INTO casbin (ptype, rule) VALUES " + req.join(", "),
            values
        );
    }

    public async deletePolicies(ptype: string, ruleFilter: CasbinRuleFilter, fieldIndex?: number): Promise<void> {
        const values = [ptype];
        const req = `DELETE FROM casbin WHERE ptype=$${values.length} AND ` + buildRuleWhereClause(ruleFilter, values, fieldIndex);

        await this.db.query(req, values);
    }

    public async clearPolicies(): Promise<void> {
        await this.db.query("DELETE FROM casbin");
    }

    public async open(): Promise<void> {
        if (this.options.migrate === false) return;

        const client = await this.db.connect();

        await migrate({
            dbClient: client,
            direction: "up",
            count: Infinity,
            migrationsTable: "casbin_migrations",
            dir: path.join(__dirname, "..", "migrations"),
            ignorePattern: "(.*\\.ts)|(\\..*)",
            log: () => void 0
        });

        await client.release();
    }

    public async close(): Promise<void> {
        await this.db.end();
    }
}

//#region Private Functions

function buildWhereClause(filter: CasbinFilter): [string, string[]] {
    if (!filter) {
        return ["", []];
    }

    const values: string[] = [];
    const res: string[] = [];

    Object.keys(filter).forEach(ptype => {
        if (!filter[ptype] || !filter[ptype].length) return;

        values.push(ptype)
        res.push(`(ptype = $${values.length} AND (${buildRuleWhereClause(filter[ptype], values)}))`);
    });

    return [
        res.length ? " WHERE " + res.join(" OR ") : "",
        values
    ];
}

function buildRuleWhereClause(ruleFilter: CasbinRuleFilter, values: string[], fieldIndex = 0): string {
    const res: string[] = [];

    ruleFilter.forEach((value, i) => {
        if (value === null || value === "" || typeof value === "undefined") return;

        if (value.startsWith("regex:")) {
            values.push(value.replace("regex:", ""));
            res.push(`rule->>${i + fieldIndex} ~ $${values.length}`);
        }
        else if (value.startsWith("like:")) {
            values.push(value.replace("like:", ""));
            res.push(`rule->>${i + fieldIndex} ~~ $${values.length}`);
        }
        else {
            values.push(value);
            res.push(`rule->>${i + fieldIndex} = $${values.length}`);
        }
    });

    return res.join(" AND ");
}

//#endregion
