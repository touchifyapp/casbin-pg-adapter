/* eslint @typescript-eslint/no-explicit-any: 0 */

import { Duplex } from "stream";
import { ConnectionOptions } from "tls";

export type CasbinRuleFilter = Array<string | null | undefined>;
export type CasbinFilter = Record<string, CasbinRuleFilter>;

export interface CasbinRule {
    ptype: string;
    rule: string[];
}

export interface PostgresAdapaterOptions {
    // Custom options
    migrate?: boolean;
    dbClient?: (exec: (client: any) => Promise<any>) => Promise<any>;

    // Client Config
    user?: string;
    database?: string;
    password?: string;
    port?: number;
    host?: string;
    connectionString?: string;
    keepAlive?: boolean;
    stream?: Duplex;
    statement_timeout?: false | number;
    parseInputDatesAsUTC?: boolean;
    ssl?: boolean | ConnectionOptions;
    query_timeout?: number;
    keepAliveInitialDelayMillis?: number;
    idle_in_transaction_session_timeout?: number;

    // Pool Config
    poolSize?: number;
    poolIdleTimeout?: number;
    reapIntervalMillis?: number;
    binary?: boolean;
    parseInt8?: boolean;
}
