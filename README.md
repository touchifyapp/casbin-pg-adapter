# PostgreSQL Casbin Adapter

[![NPM version](https://img.shields.io/npm/v/casbin-pg-adapter.svg?style=flat-square)](https://npmjs.org/package/casbin-pg-adapter)
[![NPM download](https://img.shields.io/npm/dm/casbin-pg-adapter.svg?style=flat-square)](https://npmjs.org/package/casbin-pg-adapter)
![Run Tests](https://github.com/touchifyapp/casbin-pg-adapter/workflows/Run%20Tests/badge.svg?branch=master&event=push)
[![Coverage Status](https://coveralls.io/repos/github/touchifyapp/casbin-pg-adapter/badge.svg?branch=master)](https://coveralls.io/github/touchifyapp/casbin-pg-adapter?branch=master)

[PostgreSQL](https://www.postgresql.org/) native adapter for [Node-Casbin](https://github.com/casbin/node-casbin). With this library, Node-Casbin can load policy from PosgreSQL database or save policy to it. It supports loading filtered policies and is built for improving performances in PostgreSQL. It uses [node-postgres](https://node-postgres.com/) to connect to PostgreSQL.

`casbin-pg-adapter` also adds advanced filtering capability. You can filter using `LIKE` or `regexp` expressions when using `loadFilteredPolicy`.

## Installation

```bash
npm install casbin-pg-adapter
```

## Simple example

```typescript
import { newEnforcer } from "casbin";
import PostgresAdapter from "casbin-pg-adapter";

async function myFunction() {
    // Initialize a Postgres adapter and use it in a Node-Casbin enforcer:
    // The adapter can not automatically create database.
    // But the adapter will automatically and use the table named "casbin_rule".
    // I think ORM should not automatically create databases.  
    const a = await PostgresAdapter.newAdapter({
        connectionString: "postgresql://casbin:casbin@localhost:5432/casbin"
    });

    const e = await newEnforcer("examples/rbac_model.conf", a);

    // Load the policy from DB.
    await e.loadPolicy();

    // Check the permission.
    e.enforce("alice", "data1", "read");

    // Modify the policy.
    // await e.addPolicy(...);
    // await e.removePolicy(...);

    // Save the policy back to DB.
    await e.savePolicy();
}
```

## Filtering example

```typescript
import { newEnforcer } from "casbin";
import PostgresAdapter from "casbin-pg-adapter";

async function myFunction() {
    const a = await PostgresAdapter.newAdapter({
        connectionString: "postgresql://casbin:casbin@localhost:5432/casbin"
    });

    const e = await newEnforcer("examples/rbac_model.conf", a);

    // Load the filtered policy from DB.
    await e.loadFilteredPolicy({
        p: ["alice"],
        g: ["", "role:admin"]
    });

    // Check the permission.
    e.enforce("alice", "data1", "read");
}
```

## Advanced filtering example

```typescript
import { newEnforcer } from "casbin";
import PostgresAdapter from "casbin-pg-adapter";

async function myFunction() {
    const a = await PostgresAdapter.newAdapter({
        connectionString: "postgresql://casbin:casbin@localhost:5432/casbin"
    });

    const e = await newEnforcer("examples/rbac_model.conf", a);

    // Load the filtered policy from DB.
    await e.loadFilteredPolicy({
        p: ["regex:(role:.*)|(alice)"],
        g: ["", "like:role:%"]
    });

    // Check the permission.
    e.enforce("alice", "data1", "read");
}
```

## Configuration

You can pass any [node-postgres](https://node-postgres.com/) options to the Adapter.
See `node-postgres` documentation: [Connecting to PostgreSQL](https://node-postgres.com/features/connecting#Programmatic).

## Additional configurations

#### Avoid database migration

Additionnally, you can pass the following option to the Adapter:
 * `migrate` (*Boolean*): If set to `false`, the Adapter will not apply migration when starting.

**Note:** If you use this parameter, you should apply migration manually:

```typescript
async function startup(): Promise<void> {
    PostgresAdapter.migrate({
        connectionString: "postgresql://casbin:casbin@localhost:5432/casbin"
    });
}

async function createEnforcer(): Promise<Enforcer> {
    const a = await PostgresAdapter.newAdapter({
        connectionString: "postgresql://casbin:casbin@localhost:5432/casbin",
        migrate: false
    });

    return newEnforcer("examples/rbac_model.conf", a);
}
```

#### Disabling filtered behavior

If you want to use the `savePolicy` feature from `node-casbin`, you have to disable the filtered behavior of `PostgresAdapter`.
You can do it by calling `enableFiltered` on the adapter:

```typescript
a.enableFiltered(false);
```

## Getting Help

- [Node-Casbin](https://github.com/casbin/node-casbin)
- [Casbin-PG-Adapter](https://github.com/touchifyapp/casbin-pg-adapter)

## License

This project is under MIT License. See the [LICENSE](LICENSE) file for the full license text.

