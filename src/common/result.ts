export type Result<T, E = Error> = { ok: true; data: T } | { ok: false; error: E };

export function Ok<T>(data: T): Result<T, never> {
  return { ok: true, data };
}

export function Err<E>(error: E): Result<never, E> {
  return { ok: false, error };
}
