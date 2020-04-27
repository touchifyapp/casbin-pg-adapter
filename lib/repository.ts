import * as path from "path";

import { Pool, PoolClient } from "pg";
import migrate from "node-pg-migrate";

import {
    CasbinRule,

    CasbinFilter,
    CasbinRuleFilter,

    PostgresAdapaterOptions
} from "./model";

export class CasbinRepository {
    private readonly options: PostgresAdapaterOptions;
    private readonly db: Pool | undefined;
    private readonly dbClient: <T>(cb: (client: PoolClient) => Promise<T>) => Promise<T>;

    public constructor(options: PostgresAdapaterOptions = {}) {
        this.options = options;
        if (options.dbClient) {
            this.dbClient = options.dbClient;
        }
        else {
            this.db = new Pool(options);
            this.dbClient = buildDbClientFactory(this.db);
        }
    }

    public async getAllPolicies(): Promise<CasbinRule[]> {
        return this.dbClient(async (client) => {
            const { rows } = await client.query("SELECT ptype, rule FROM casbin");
            return rows;
        });
    }

    public async getFilteredPolicies(filter: CasbinFilter): Promise<CasbinRule[]> {
        const [where, values] = buildWhereClause(filter);

        return this.dbClient(async (client) => {
            const { rows } = await client.query("SELECT ptype, rule FROM casbin" + where, values);
            return rows;
        });
    }

    public async insertPolicy(ptype: string, rule: string[]): Promise<void> {
        return this.dbClient(async (client) => {
            await client.query(
                "INSERT INTO casbin (ptype, rule) VALUES ($1, $2::jsonb)",
                [ptype, JSON.stringify(rule)]
            );
        });
    }

    public async insertPolicies(rules: CasbinRule[]): Promise<void> {
        const req: string[] = [];
        const values: string[] = [];

        let i = 1;
        for (const { ptype, rule } of rules) {
            req.push(`($${i++}, $${i++}::jsonb)`);
            values.push(ptype, JSON.stringify(rule));
        }

        return this.dbClient(async (client) => {
            await client.query(
                "INSERT INTO casbin (ptype, rule) VALUES " + req.join(", "),
                values
            );
        });
    }

    public async deletePolicies(ptype: string, ruleFilter: CasbinRuleFilter, fieldIndex?: number): Promise<void> {
        const values = [ptype];
        const req = `DELETE FROM casbin WHERE ptype=$${values.length} AND ` + buildRuleWhereClause(ruleFilter, values, fieldIndex);

        return this.dbClient(async (client) => {
            await client.query(req, values);
        });
    }

    public async clearPolicies(): Promise<void> {
        return this.dbClient(async (client) => {
            await client.query("DELETE FROM casbin");
        });
    }

    public async open(): Promise<void> {
        if (this.options.migrate !== false) {
            await this.migrate();
        }
    }

    public async migrate(): Promise<void> {
        return this.dbClient(async (client) => {
            await migrate({
                dbClient: client,
                direction: "up",
                count: Infinity,
                migrationsTable: "casbin_migrations",
                dir: path.join(__dirname, "..", "migrations"),
                ignorePattern: "(.*\\.ts)|(\\..*)",
                log: () => void 0
            });

        });
    }

    public async close(): Promise<void> {
        if (this.db) {
            await this.db.end();
        }
    }
}

//#region Private Functions

function buildDbClientFactory(pool: Pool): <T>(cb: (client: PoolClient) => Promise<T>) => Promise<T> {
    return async function batch<T>(exec: (client: PoolClient) => Promise<T>): Promise<T> {
        const client = await pool.connect();
        try {
            const res = await Promise.resolve(exec(client));
            client.release();
            return res;
        }
        catch (err) {
            client.release();
            throw err;
        }
    }
}

function buildWhereClause(filter: CasbinFilter): [string, string[]] {
    if (!filter) {
        return ["", []];
    }

    const values: string[] = [];
    const res: string[] = [];

    Object.keys(filter).forEach(ptype => {
        values.push(ptype);
        let typePredicate = `ptype = $${values.length}`;

        if (filter[ptype] && filter[ptype].length) {
            const rulePredicate = buildRuleWhereClause(filter[ptype], values);
            if (rulePredicate) {
                typePredicate = `(${typePredicate} AND (${rulePredicate}))`
            }
        }

        res.push(typePredicate);
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
