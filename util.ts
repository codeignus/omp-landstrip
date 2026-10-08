// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

export { expandHomePath, isRecord } from '@landstrip/landstrip-api/shared';

export function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export class AsyncQueue {
  private tail = Promise.resolve();
  private generation = 0;
  private resetWaiters: Array<() => void> = [];

  async acquire(
    signal?: AbortSignal,
    cancellationMessage = 'Request cancelled',
  ): Promise<() => void> {
    if (signal?.aborted) throw new Error(cancellationMessage);
    const generation = this.generation;
    let release: (() => void) | undefined;
    const previous = this.tail;
    this.tail = new Promise<void>((resolve) => {
      release = resolve;
    });

    const finish = (): void => {
      release?.();
    };

    let wakeReset: (() => void) | undefined;
    const resetSignal = new Promise<void>((resolve) => {
      wakeReset = resolve;
      this.resetWaiters.push(resolve);
    });

    const dropResetWaiter = (): void => {
      if (!wakeReset) return;
      const index = this.resetWaiters.indexOf(wakeReset);
      if (index >= 0) this.resetWaiters.splice(index, 1);
      wakeReset = undefined;
    };

    try {
      if (!signal) {
        await Promise.race([previous, resetSignal]);
      } else {
        let abort: (() => void) | undefined;
        try {
          await Promise.race([
            previous,
            resetSignal,
            new Promise<never>((_resolve, reject) => {
              abort = () => reject(new Error(cancellationMessage));
              signal.addEventListener('abort', abort, { once: true });
            }),
          ]);
        } finally {
          if (abort) signal.removeEventListener('abort', abort);
        }
      }
      if (this.generation !== generation) {
        throw new Error(cancellationMessage);
      }
      return finish;
    } catch (error) {
      // Advance the abandoned chain so later waiters still make progress.
      void previous.finally(finish);
      throw error;
    } finally {
      dropResetWaiter();
    }
  }

  reset(): void {
    this.generation += 1;
    this.tail = Promise.resolve();
    const waiters = this.resetWaiters.splice(0);
    for (const wake of waiters) wake();
  }
}

export function combineAbortSignals(...sources: Array<AbortSignal | undefined>): {
  signal: AbortSignal;
  dispose: () => void;
} {
  const signals = sources.filter((source): source is AbortSignal => source !== undefined);
  const only = signals[0];
  if (signals.length === 1 && only) return { signal: only, dispose: () => undefined };

  const controller = new AbortController();
  const abort = (): void => controller.abort();
  for (const signal of signals) signal.addEventListener('abort', abort, { once: true });
  if (signals.some((signal) => signal.aborted)) controller.abort();

  return {
    signal: controller.signal,
    dispose: () => {
      for (const signal of signals) signal.removeEventListener('abort', abort);
    },
  };
}

export class PermissionPromptCoordinator {
  private readonly queue = new AsyncQueue();
  private resetController = new AbortController();

  async resolve<T>(
    current: () => T | undefined,
    request: (signal: AbortSignal) => Promise<T>,
    signal?: AbortSignal,
  ): Promise<T> {
    const immediate = current();
    if (immediate !== undefined) return immediate;

    const combined = combineAbortSignals(signal, this.resetController.signal);
    let release: (() => void) | undefined;
    try {
      release = await this.queue.acquire(combined.signal, 'Permission request cancelled');
      const resolved = current();
      if (resolved !== undefined) return resolved;
      if (combined.signal.aborted) throw new Error('Permission request cancelled');
      const result = await request(combined.signal);
      if (combined.signal.aborted) throw new Error('Permission request cancelled');
      return result;
    } finally {
      release?.();
      combined.dispose();
    }
  }

  reset(): void {
    const controller = this.resetController;
    this.resetController = new AbortController();
    this.queue.reset();
    controller.abort();
  }
}

const fileMutationQueues = new Map<string, AsyncQueue>();

/**
 * Serialize config-file mutations per path. Replaces the pi-host
 * withFileMutationQueue, which omp does not export.
 */
export async function withFileMutationQueue(path: string, fn: () => Promise<void>): Promise<void> {
  let queue = fileMutationQueues.get(path);
  if (!queue) {
    queue = new AsyncQueue();
    fileMutationQueues.set(path, queue);
  }
  const release = await queue.acquire();
  try {
    await fn();
  } finally {
    release();
  }
}
