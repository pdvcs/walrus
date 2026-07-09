import { Pool, PoolClient } from "pg";

/**
 * Anything that can run a parameterized query: the shared pool, or a checked-out
 * client mid-transaction. Query helpers accept this so they compose inside the
 * batch transactions the vuln sync pipeline manages (plan §5).
 */
export type Queryable = Pool | PoolClient;
