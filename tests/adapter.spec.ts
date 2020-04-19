import PostgresAdapter from "../";
import { CasbinRepository } from "../lib/repository";

import {
    Model
} from "casbin";

import {
    connectionString,

    buildAdapter,
    buildModel,

    cleanDB,
    cleanAdapter,
    cleanEnv,

    importSampleData,
    getSamplePolicies,
    getSampleRoles,

    dbGetAll,
    getRulesFromModel
} from "./helpers";

const
    POLICIES = getSamplePolicies(),
    ROLES = getSampleRoles();

afterAll(cleanEnv);

describe("PostgresAdapter", () => {
    let a: PostgresAdapter;

    describe("#loadPolicy()", () => {
        let m: Model;

        beforeAll(async () => {
            a = await buildAdapter();
            await importSampleData();
        });
        afterAll(() => Promise.all([
            cleanDB(),
            cleanAdapter(a)
        ]));

        beforeEach(() => { m = buildModel(); });
        afterEach(() => { m.clearPolicy(); });

        test("should resolves with void", async () => {
            const res = await a.loadPolicy(m);
            expect(res).toBeUndefined();
        });

        test("should fetch policies from DB into Model", async () => {
            await a.loadPolicy(m);

            expect(getRulesFromModel(m, "p")).toEqual(POLICIES);
            expect(getRulesFromModel(m, "g")).toEqual(ROLES);
        });
    });

    describe("#loadFilteredPolicy()", () => {
        let m: Model;

        beforeAll(async () => {
            a = await buildAdapter();
            await importSampleData();
        });
        afterAll(() => Promise.all([
            cleanDB(),
            cleanAdapter(a)
        ]));

        beforeEach(() => { m = buildModel(); });
        afterEach(() => { m.clearPolicy(); });

        test("should resolves with void", async () => {
            const res = await a.loadFilteredPolicy(m, { p: ["", "data1"], g: ["", "role:admin"] });
            expect(res).toBeUndefined();
        });

        test("should fetch filtered policies from DB into Model", async () => {
            await a.loadFilteredPolicy(m, { p: ["", "data1"], g: ["", "role:admin"] });

            expect(getRulesFromModel(m, "p")).toEqual(POLICIES.filter(p => p.rule[1] === "data1"));
            expect(getRulesFromModel(m, "g")).toEqual(ROLES.filter(p => p.rule[1] === "role:admin"));
        });

        test("should allow LIKE expressions to filter policies from DB into Model", async () => {
            await a.loadFilteredPolicy(m, { p: ["like:role:%"], g: ["", "like:role:%"] });

            expect(getRulesFromModel(m, "p")).toEqual(POLICIES.filter(p => p.rule[0].startsWith("role:")));
            expect(getRulesFromModel(m, "g")).toEqual(ROLES.filter(p => p.rule[1].startsWith("role:")));
        });

        test("should allow regex expressions to filter policies from DB into Model", async () => {
            await a.loadFilteredPolicy(m, { p: ["regex:(role:.*)|(user1)"], g: ["", "regex:role:.*"] });

            expect(getRulesFromModel(m, "p")).toEqual(POLICIES.filter(p => p.rule[0].startsWith("role:") || p.rule[0] === "user1"));
            expect(getRulesFromModel(m, "g")).toEqual(ROLES.filter(p => p.rule[1].startsWith("role:")));
        });

        test("should load all policies if no filter is passed", async () => {
            await a.loadFilteredPolicy(m, null as any);

            expect(getRulesFromModel(m, "p")).toEqual(POLICIES);
            expect(getRulesFromModel(m, "g")).toEqual(ROLES);
        });

        test("should load all policies if empty filter is passed", async () => {
            await a.loadFilteredPolicy(m, {});

            expect(getRulesFromModel(m, "p")).toEqual(POLICIES);
            expect(getRulesFromModel(m, "g")).toEqual(ROLES);
        });

        test("should take all policies with ptype filter = null", async () => {
            await a.loadFilteredPolicy(m, {
                p: ["", "data1"],
                g: null as any
            });

            expect(getRulesFromModel(m, "p")).toEqual(POLICIES.filter(p => p.rule[1] === "data1"));
            expect(getRulesFromModel(m, "g")).toEqual(ROLES);
        });

        test("should take all policies with ptype filter = empty array", async () => {
            await a.loadFilteredPolicy(m, {
                p: ["", "data1"],
                g: []
            });

            expect(getRulesFromModel(m, "p")).toEqual(POLICIES.filter(p => p.rule[1] === "data1"));
            expect(getRulesFromModel(m, "g")).toEqual(ROLES);
        });

        test("should take all policies with ptype filter = array with only empty values", async () => {
            await a.loadFilteredPolicy(m, {
                p: ["", "data1"],
                g: ["", ""]
            });

            expect(getRulesFromModel(m, "p")).toEqual(POLICIES.filter(p => p.rule[1] === "data1"));
            expect(getRulesFromModel(m, "g")).toEqual(ROLES);
        });

        test("should not take policies with ptype not specified in filter", async () => {
            await a.loadFilteredPolicy(m, {
                p: ["", "data1"]
            });

            expect(getRulesFromModel(m, "p")).toEqual(POLICIES.filter(p => p.rule[1] === "data1"));
            expect(getRulesFromModel(m, "g")).toEqual([]);
        });
    });

    describe("#addPolicy()", () => {
        beforeEach(async () => { a = await buildAdapter(); });
        afterEach(() => Promise.all([cleanDB(), cleanAdapter(a)]));

        test("should resolves with void", async () => {
            const res = await a.addPolicy("p", "p", ["alice", "data5", "read"]);
            expect(res).toBeUndefined();
        });

        test("should add policy in DB", async () => {
            await a.addPolicy("p", "p", ["alice", "data5", "read"]);
            const rules = await dbGetAll();
            expect(rules).toEqual([{ ptype: "p", rule: ["alice", "data5", "read"] }]);
        });
    });

    describe("#removePolicy()", () => {
        beforeAll(async () => {
            a = await buildAdapter();
            await importSampleData();
        });
        afterAll(() => Promise.all([
            cleanDB(),
            cleanAdapter(a)
        ]));

        test("should resolves with void", async () => {
            const res = await a.removePolicy("p", "p", POLICIES[0].rule);
            expect(res).toBeUndefined();
        });

        test("should remove policy from DB", async () => {
            await a.removePolicy("p", "p", POLICIES[1].rule);
            const rules = await dbGetAll();
            expect(rules).not.toContainEqual(POLICIES[1]);
        });
    });

    describe("#removeFilteredPolicy()", () => {
        beforeAll(async () => {
            a = await buildAdapter();
            await importSampleData();
        });
        afterAll(() => Promise.all([
            cleanDB(),
            cleanAdapter(a)
        ]));

        test("should resolves with void", async () => {
            const res = await a.removeFilteredPolicy("p", "p", 0, "user2");
            expect(res).toBeUndefined();
        });

        test("should remove policies from DB", async () => {
            await a.removeFilteredPolicy("p", "p", 0, "user1");

            const rules = await dbGetAll();
            expect(rules).toEqual(
                expect.not.arrayContaining(
                    POLICIES.filter(r => r.rule[0] === "user1")
                )
            );
        });
    });

    describe("#savePolicy()", () => {
        let m: Model;

        beforeEach(async () => {
            a = await buildAdapter();
            m = await buildModel();
        });
        afterEach(() => Promise.all([
            cleanDB(),
            cleanAdapter(a),
            m.clearPolicy()
        ]));

        test("should resolves with true", async () => {
            m.addPolicy("p", "p", ["alice", "data", "read"]);
            const res = await a.savePolicy(m);
            expect(res).toBe(true);
        });

        test("should resolves with false if no changes to be submited", async () => {
            const res = await a.savePolicy(m);
            expect(res).toBe(false);
        });

        test("should add policies in DB", async () => {
            m.addPolicy("p", "p", ["alice", "data", "read"]);
            m.addPolicy("p", "p", ["bob", "data", "write"]);
            m.addPolicy("p", "p", ["john", "data", "delete"]);
            m.addPolicy("g", "g", ["john", "role:admin"]);

            await a.savePolicy(m);

            const rules = await dbGetAll();
            expect(rules).toEqual(
                expect.arrayContaining([
                    { ptype: "p", rule: ["alice", "data", "read"] },
                    { ptype: "p", rule: ["bob", "data", "write"] },
                    { ptype: "p", rule: ["john", "data", "delete"] },
                    { ptype: "g", rule: ["john", "role:admin"] }
                ])
            );
        });

        test("should clear database before syncing", async () => {
            await importSampleData();

            m.addPolicy("p", "p", ["alice", "data", "read"]);
            m.addPolicy("p", "p", ["bob", "data", "write"]);
            m.addPolicy("p", "p", ["john", "data", "delete"]);

            await a.savePolicy(m);

            const rules = await dbGetAll();
            expect(rules).toEqual(
                expect.not.arrayContaining(POLICIES)
            );
        });
    });

    describe(".newAdapater()", () => {
        let a: PostgresAdapter;
        let spy: jest.SpyInstance;
        beforeEach(() => { spy = jest.spyOn(CasbinRepository.prototype, "migrate"); });
        afterEach(async () => { spy.mockRestore(); await a.close(); });

        test("should resolves with PostgresAdapter", async () => {
            a = await PostgresAdapter.newAdapter({ connectionString });
            expect(a).toBeInstanceOf(PostgresAdapter);
        });

        test("should call repo.migrate() if not migrate option is passed", async () => {
            a = await PostgresAdapter.newAdapter({ connectionString });
            expect(spy).toBeCalledTimes(1);
        });

        test("should not call repo.migrate() if migrate = false", async () => {
            a = await PostgresAdapter.newAdapter({ connectionString, migrate: false });
            expect(spy).not.toBeCalled();
        });
    });

    describe(".migrate()", () => {
        let spy: jest.SpyInstance;
        beforeEach(() => { spy = jest.spyOn(CasbinRepository.prototype, "migrate"); });
        afterEach(() => { spy.mockRestore(); });

        test("should resolves with void", async () => {
            const res = await PostgresAdapter.migrate({ connectionString });
            expect(res).toBeUndefined();
        });

        test("should call repo.migrate()", async () => {
            await PostgresAdapter.migrate({ connectionString });
            expect(spy).toBeCalledTimes(1);
        });
    });

});