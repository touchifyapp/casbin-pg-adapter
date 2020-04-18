import PostgresAdapter from "../";

import {
    Enforcer,
    Model
} from "casbin";

import {
    buildEnforcer,
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

    describe("methods", () => {
        let a: PostgresAdapter;

        describe(".loadPolicy()", () => {
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

        describe(".loadFilteredPolicy()", () => {
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
                const res = await a.loadFilteredPolicy(m, { p: ["", "data1"], g: ["role1"] });
                expect(res).toBeUndefined();
            });

            test("should fetch filtered policies from DB into Model", async () => {
                await a.loadFilteredPolicy(m, { p: ["", "data1"], g: ["role1"] });

                expect(getRulesFromModel(m, "p")).toEqual(POLICIES.filter(p => p.rule[1] === "data1"));
                expect(getRulesFromModel(m, "g")).toEqual(ROLES.filter(p => p.rule[0] === "role1"));
            });
        });

        describe(".addPolicy()", () => {
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

        describe(".removePolicy()", () => {
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

        describe(".removeFilteredPolicy()", () => {
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

        describe(".savePolicy()", () => {
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

                await a.savePolicy(m);

                const rules = await dbGetAll();
                expect(rules).toEqual(
                    expect.arrayContaining([
                        { ptype: "p", rule: ["alice", "data", "read"] },
                        { ptype: "p", rule: ["bob", "data", "write"] },
                        { ptype: "p", rule: ["john", "data", "delete"] }
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

    });

    describe("Enforcer", () => {
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
                const res = await e.loadFilteredPolicy({ p: ["", "data1"], g: ["role1"] });
                expect(res).toBe(true);
            });

            test("should fetch filtered policies from DB into Model", async () => {
                await e.loadFilteredPolicy({ p: ["", "data1"], g: ["role1"] });

                expect(getRulesFromModel(e.getModel(), "p")).toEqual(POLICIES.filter(p => p.rule[1] === "data1"));
                expect(getRulesFromModel(e.getModel(), "g")).toEqual(ROLES.filter(p => p.rule[0] === "role1"));
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

                await a.savePolicy(m);

                const rules = await dbGetAll();
                expect(rules).toEqual(
                    expect.arrayContaining([
                        { ptype: "p", rule: ["alice", "data", "read"] },
                        { ptype: "p", rule: ["bob", "data", "write"] },
                        { ptype: "p", rule: ["john", "data", "delete"] }
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

});