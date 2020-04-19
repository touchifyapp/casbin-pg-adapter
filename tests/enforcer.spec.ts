import PostgresAdapter from "../";

import {
    Enforcer,
    Model
} from "casbin";

import {
    buildEnforcer,
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
    let m: Model;
    let a: PostgresAdapter;
    let e: Enforcer;

    describe(".loadPolicy()", () => {
        beforeAll(async () => {
            [m, a, e] = await buildEnforcer();
            await importSampleData();
        });
        afterAll(async () => {
            await cleanAdapter(a);
            await cleanDB();
        });

        beforeEach(() => { m = buildModel(); });
        afterEach(() => { m.clearPolicy(); });

        test("should resolves with void", async () => {
            const res = await e.loadPolicy();
            expect(res).toBeUndefined();
        });

        test("should fetch policies from DB into Model", async () => {
            await e.loadPolicy();

            expect(getRulesFromModel(e.getModel(), "p")).toEqual(POLICIES);
            expect(getRulesFromModel(e.getModel(), "g")).toEqual(ROLES);
        });
    });

    describe(".loadFilteredPolicy()", () => {
        beforeAll(async () => {
            [m, a, e] = await buildEnforcer();
            await importSampleData();
        });
        afterAll(() => Promise.all([
            cleanDB(),
            cleanAdapter(a)
        ]));

        beforeEach(() => { m = buildModel(); });
        afterEach(() => { m.clearPolicy(); });

        test("should resolves with true", async () => {
            const res = await e.loadFilteredPolicy({ p: ["", "data1"], g: ["", "role:admin"] });
            expect(res).toBe(true);
        });

        test("should fetch filtered policies from DB into Model", async () => {
            await e.loadFilteredPolicy({ p: ["", "data1"], g: ["", "role:admin"] });

            expect(getRulesFromModel(e.getModel(), "p")).toEqual(POLICIES.filter(p => p.rule[1] === "data1"));
            expect(getRulesFromModel(e.getModel(), "g")).toEqual(ROLES.filter(p => p.rule[1] === "role:admin"));
        });

        test("should allow LIKE expressions to filter policies from DB into Model", async () => {
            await e.loadFilteredPolicy({ p: ["like:role:%"], g: ["", "like:role:%"] });

            expect(getRulesFromModel(e.getModel(), "p")).toEqual(POLICIES.filter(p => p.rule[0].startsWith("role:")));
            expect(getRulesFromModel(e.getModel(), "g")).toEqual(ROLES.filter(p => p.rule[1].startsWith("role:")));
        });

        test("should allow regex expressions to filter policies from DB into Model", async () => {
            await e.loadFilteredPolicy({ p: ["regex:(role:.*)|(user1)"], g: ["", "regex:role:.*"] });

            expect(getRulesFromModel(e.getModel(), "p")).toEqual(POLICIES.filter(p => p.rule[0].startsWith("role:") || p.rule[0] === "user1"));
            expect(getRulesFromModel(e.getModel(), "g")).toEqual(ROLES.filter(p => p.rule[1].startsWith("role:")));
        });

        test("should load all policies if no filter is passed", async () => {
            await e.loadFilteredPolicy(null as any);

            expect(getRulesFromModel(e.getModel(), "p")).toEqual(POLICIES);
            expect(getRulesFromModel(e.getModel(), "g")).toEqual(ROLES);
        });

        test("should load all policies if empty filter is passed", async () => {
            await e.loadFilteredPolicy({} as any);

            expect(getRulesFromModel(e.getModel(), "p")).toEqual(POLICIES);
            expect(getRulesFromModel(e.getModel(), "g")).toEqual(ROLES);
        });

        test("should take all policies with ptype filter = null", async () => {
            await e.loadFilteredPolicy({
                p: ["", "data1"],
                g: null as any
            });

            expect(getRulesFromModel(e.getModel(), "p")).toEqual(POLICIES.filter(p => p.rule[1] === "data1"));
            expect(getRulesFromModel(e.getModel(), "g")).toEqual(ROLES);
        });

        test("should take all policies with ptype filter = empty array", async () => {
            await e.loadFilteredPolicy({
                p: ["", "data1"],
                g: []
            });

            expect(getRulesFromModel(e.getModel(), "p")).toEqual(POLICIES.filter(p => p.rule[1] === "data1"));
            expect(getRulesFromModel(e.getModel(), "g")).toEqual(ROLES);
        });

        test("should take all policies with ptype filter = array with only empty values", async () => {
            await e.loadFilteredPolicy({
                p: ["", "data1"],
                g: ["", ""]
            });

            expect(getRulesFromModel(e.getModel(), "p")).toEqual(POLICIES.filter(p => p.rule[1] === "data1"));
            expect(getRulesFromModel(e.getModel(), "g")).toEqual(ROLES);
        });

        test("should not take policies with ptype not specified in filter", async () => {
            await e.loadFilteredPolicy({
                p: ["", "data1"]
            } as any);

            expect(getRulesFromModel(e.getModel(), "p")).toEqual(POLICIES.filter(p => p.rule[1] === "data1"));
            expect(getRulesFromModel(e.getModel(), "g")).toEqual([]);
        });
    });

    describe(".addPolicy()", () => {
        beforeAll(async () => {
            [m, a, e] = await buildEnforcer();
        });
        afterAll(async () => {
            await cleanAdapter(a);
            await cleanDB();
        });

        test("should resolves with true", async () => {
            const res = await e.addPolicy("alice", "data1", "read");
            expect(res).toBe(true);
        });

        test("should not add into DB if autoSave is disabled", async () => {
            e.enableAutoSave(false);

            await e.addPolicy("alice", "data2", "read");

            const rules = await dbGetAll();
            expect(rules).not.toContainEqual({ ptype: "p", rule: ["alice", "data2", "read"] });
        });

        test("should add into DB if autoSave is enabled", async () => {
            e.enableAutoSave(true);

            await e.addPolicy("alice", "data3", "read");

            const rules = await dbGetAll();
            expect(rules).toContainEqual({ ptype: "p", rule: ["alice", "data3", "read"] });
        });

    });

    describe(".removePolicy()", () => {
        beforeAll(async () => {
            [m, a, e] = await buildEnforcer();
            await importSampleData();
            await e.loadPolicy();
        });
        afterAll(async () => {
            await cleanAdapter(a);
            await cleanDB();
        });

        test("should resolves with true", async () => {
            const res = await e.removePolicy(...POLICIES[0].rule);
            expect(res).toBe(true);
        });

        test("should not remove from DB if autoSave is disabled", async () => {
            e.enableAutoSave(false);

            await e.removePolicy(...POLICIES[1].rule);

            const rules = await dbGetAll();
            expect(rules).toContainEqual(POLICIES[1]);
        });

        test("should remove from DB if autoSave is enabled", async () => {
            e.enableAutoSave(true);

            await e.removePolicy(...POLICIES[2].rule);

            const rules = await dbGetAll();
            expect(rules).not.toContainEqual(POLICIES[2]);
        });

    });

    describe(".removeFilteredPolicy()", () => {
        beforeAll(async () => {
            [m, a, e] = await buildEnforcer();
            await importSampleData();
            await e.loadPolicy();
        });
        afterAll(async () => {
            await cleanAdapter(a);
            await cleanDB();
        });

        test("should resolves with true", async () => {
            const res = await e.removeFilteredPolicy(1, POLICIES[3].rule[1]);
            expect(res).toBe(true);
        });

        test("should not remove from DB if autoSave is disabled", async () => {
            e.enableAutoSave(false);

            await e.removeFilteredPolicy(1, POLICIES[4].rule[1]);

            const rules = await dbGetAll();
            expect(rules).toEqual(
                expect.arrayContaining(POLICIES.filter(p => p.rule[1] === POLICIES[4].rule[1]))
            );
        });

        test("should remove from DB if autoSave is enabled", async () => {
            e.enableAutoSave(true);

            await e.removeFilteredPolicy(1, POLICIES[0].rule[1]);

            const rules = await dbGetAll();
            expect(rules).toEqual(
                expect.not.arrayContaining(POLICIES.filter(p => p.rule[1] === POLICIES[0].rule[1]))
            );
        });

    });

    describe(".addGroupingPolicy()", () => {
        beforeAll(async () => {
            [m, a, e] = await buildEnforcer();
        });
        afterAll(async () => {
            await cleanAdapter(a);
            await cleanDB();
        });

        test("should resolves with true", async () => {
            const res = await e.addGroupingPolicy("role1", "user1");
            expect(res).toBe(true);
        });

        test("should not add into DB if autoSave is disabled", async () => {
            e.enableAutoSave(false);

            await e.addGroupingPolicy("role1", "user2");

            const rules = await dbGetAll();
            expect(rules).not.toContainEqual({ ptype: "g", rule: ["role1", "user2"] });
        });

        test("should add into DB if autoSave is enabled", async () => {
            e.enableAutoSave(true);

            await e.addGroupingPolicy("role1", "user3");

            const rules = await dbGetAll();
            expect(rules).toContainEqual({ ptype: "g", rule: ["role1", "user3"] });
        });

    });

    describe(".removeGroupingPolicy()", () => {
        beforeAll(async () => {
            [m, a, e] = await buildEnforcer();
            await importSampleData();
            await e.loadPolicy();
        });
        afterAll(async () => {
            await cleanAdapter(a);
            await cleanDB();
        });

        test("should resolves with true", async () => {
            const res = await e.removeGroupingPolicy(...ROLES[0].rule);
            expect(res).toBe(true);
        });

        test("should not remove from DB if autoSave is disabled", async () => {
            e.enableAutoSave(false);

            await e.removeGroupingPolicy(...ROLES[1].rule);

            const rules = await dbGetAll();
            expect(rules).toContainEqual(ROLES[1]);
        });

        test("should remove from DB if autoSave is enabled", async () => {
            e.enableAutoSave(true);

            await e.removeGroupingPolicy(...ROLES[2].rule);

            const rules = await dbGetAll();
            expect(rules).not.toContainEqual(ROLES[2]);
        });

    });

    describe(".removeFilteredGroupingPolicy()", () => {
        beforeAll(async () => {
            [m, a, e] = await buildEnforcer();
            await importSampleData();
            await e.loadPolicy();
        });
        afterAll(async () => {
            await cleanAdapter(a);
            await cleanDB();
        });

        test("should resolves with true", async () => {
            const res = await e.removeFilteredGroupingPolicy(1, ROLES[0].rule[1]);
            expect(res).toBe(true);
        });

        test("should not remove from DB if autoSave is disabled", async () => {
            e.enableAutoSave(false);

            await e.removeFilteredGroupingPolicy(1, ROLES[2].rule[1]);

            const rules = await dbGetAll();
            expect(rules).toEqual(
                expect.arrayContaining(ROLES.filter(p => p.rule[1] === ROLES[2].rule[1]))
            );
        });

        test("should remove from DB if autoSave is enabled", async () => {
            e.enableAutoSave(true);

            await e.removeFilteredGroupingPolicy(1, ROLES[4].rule[1]);

            const rules = await dbGetAll();
            expect(rules).toEqual(
                expect.not.arrayContaining(ROLES.filter(p => p.rule[1] === ROLES[4].rule[1]))
            );
        });

    });

    describe(".savePolicy()", () => {
        beforeAll(async () => {
            [m, a, e] = await buildEnforcer();
            a.enabledFiltered(false);
        });
        afterAll(() => Promise.all([
            cleanDB(),
            cleanAdapter(a),
            m.clearPolicy()
        ]));

        test("should resolves with true", async () => {
            m.addPolicy("p", "p", ["alice", "data", "read"]);
            const res = await e.savePolicy();
            expect(res).toBe(true);
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

        test("should rejects if adapter.isFiltered is enabled", async () => {
            a.enabledFiltered(true);

            await expect(e.savePolicy())
                .rejects.toBeInstanceOf(Error);
        });

    });

    describe(".enforce()", () => {
        beforeAll(async () => {
            [m, a, e] = await buildEnforcer();
            await importSampleData();
            await e.loadPolicy();
        });
        afterAll(async () => await Promise.all([
            cleanAdapter(a),
            cleanDB()
        ]));

        test("should allow user1 permission to read data1", async () => {
            const res = await e.enforce("user1", "data1", "read");
            expect(res).toBe(true);
        });

        test("should allow user1 permission to write data1", async () => {
            const res = await e.enforce("user1", "data1", "write");
            expect(res).toBe(true);
        });

        test("should deny user1 permission to delete data1", async () => {
            const res = await e.enforce("user1", "data1", "delete");
            expect(res).toBe(false);
        });

        test("should allow user1 permission to read any data", async () => {
            const res = await e.enforce("user1", "dataany", "read");
            expect(res).toBe(true);
        });

        test("should allow user11 permission to do anything on any data", async () => {
            const res = await e.enforce("user11", "dataany", "actionany");
            expect(res).toBe(true);
        });

    });

});