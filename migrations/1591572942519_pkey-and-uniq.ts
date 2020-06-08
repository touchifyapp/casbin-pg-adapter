/* eslint-disable @typescript-eslint/camelcase */
import { MigrationBuilder } from 'node-pg-migrate';

export async function up(pgm: MigrationBuilder): Promise<void> {
    pgm.addConstraint("casbin", "casbin_pkey", { primaryKey: "id" });
    pgm.addConstraint("casbin", "casbin_uniq_rule", { unique: "rule" });
}

export async function down(pgm: MigrationBuilder): Promise<void> {
    pgm.dropConstraint("casbin", "casbin_uniq_rule");
    pgm.dropConstraint("casbin", "casbin_pkey");
}
