import { Adapter, Helper, Model, Assertion } from "casbin";

import { CasbinRepository } from "./repository";

import {
    PostgresAdapaterOptions,

    CasbinRule,
    CasbinFilter
} from "./model";

export class PostgresAdapter implements Adapter {
    private filtered = true;
    private readonly repo: CasbinRepository;

    private constructor(options?: PostgresAdapaterOptions) {
        this.repo = new CasbinRepository(options);
    }

    public static async newAdapter(options?: PostgresAdapaterOptions): Promise<PostgresAdapter> {
        const adapter = new PostgresAdapter(options);
        await adapter.open();
        return adapter;
    }

    public static async migrate(options?: PostgresAdapaterOptions): Promise<void> {
        const repo = new CasbinRepository(options);
        await repo.migrate();
        await repo.close();
    }

    public async open(): Promise<void> {
        await this.repo.open();
    }

    public async close(): Promise<void> {
        await this.repo.close();
    }

    public isFiltered(): boolean {
        return this.filtered;
    }

    public enabledFiltered(enabled: boolean): void {
        this.filtered = enabled;
    }

    public async loadPolicy(model: Model): Promise<void> {
        const rules = await this.repo.getAllPolicies();
        loadPolicyLines(model, rules);
    }

    public async loadFilteredPolicy(model: Model, filter: CasbinFilter): Promise<void> {
        const rules = await this.repo.getFilteredPolicies(filter);
        loadPolicyLines(model, rules);
    }

    public async savePolicy(model: Model): Promise<boolean> {
        await this.repo.clearPolicies();

        const rules: CasbinRule[] = [];

        let astMap = model.model.get("p") as Map<string, Assertion>;
        for (const [ptype, ast] of astMap) {
            for (const rule of ast.policy) {
                rules.push({ ptype, rule });
            }
        }

        astMap = model.model.get("g") as Map<string, Assertion>;
        for (const [ptype, ast] of astMap) {
            for (const rule of ast.policy) {
                rules.push({ ptype, rule });
            }
        }

        if (rules.length) {
            await this.repo.insertPolicies(rules);
        }

        return rules.length > 0;
    }

    public addPolicy(sec: string, ptype: string, rule: string[]): Promise<void> {
        return this.repo.insertPolicy(ptype, rule);
    }

    public removePolicy(sec: string, ptype: string, rule: string[]): Promise<void> {
        return this.repo.deletePolicies(ptype, rule);
    }

    public removeFilteredPolicy(sec: string, ptype: string, fieldIndex: number, ...fieldValues: string[]): Promise<void> {
        return this.repo.deletePolicies(ptype, fieldValues, fieldIndex);
    }
}

function loadPolicyLines(model: Model, rules: CasbinRule[]): void {
    rules.forEach(rule => {
        Helper.loadPolicyLine(`${rule.ptype}, ${rule.rule.join(", ")}`, model);
    });
}
