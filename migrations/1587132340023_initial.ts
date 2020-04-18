import { MigrationBuilder } from "node-pg-migrate";

export function up(pgm: MigrationBuilder): void {
    pgm.createTable("casbin", {
        id: "serial",
        ptype: { type: "text", notNull: true },
        rule: { type: "jsonb", notNull: true }
    });

    pgm.addIndex("casbin", "ptype", {
        name: "idx_casbin_ptype",
        method: "btree"
    });

    pgm.sql(`CREATE INDEX idx_casbin_rule_v0 ON casbin USING btree ((rule->>0))`);
    pgm.sql(`CREATE INDEX idx_casbin_rule_v1 ON casbin USING btree ((rule->>1))`);
    pgm.sql(`CREATE INDEX idx_casbin_rule_v2 ON casbin USING btree ((rule->>2))`);
    pgm.sql(`CREATE INDEX idx_casbin_rule_v3 ON casbin USING btree ((rule->>3))`);
    pgm.sql(`CREATE INDEX idx_casbin_rule_v4 ON casbin USING btree ((rule->>4))`);
    pgm.sql(`CREATE INDEX idx_casbin_rule_v5 ON casbin USING btree ((rule->>5))`);
}

export function down(pgm: MigrationBuilder): void {
    pgm.dropIndex("casbin", "ptype", { name: "idx_casbin_ptype" });

    pgm.sql(`DROP INDEX idx_casbin_rule_v0`);
    pgm.sql(`DROP INDEX idx_casbin_rule_v1`);
    pgm.sql(`DROP INDEX idx_casbin_rule_v2`);
    pgm.sql(`DROP INDEX idx_casbin_rule_v3`);
    pgm.sql(`DROP INDEX idx_casbin_rule_v4`);
    pgm.sql(`DROP INDEX idx_casbin_rule_v5`);

    pgm.dropTable("casbin");
}
