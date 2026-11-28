// Waiting for enough answers, not all of them (#111): one slow relay mustn't
// hold up a read. Resolves with the answers in hand once `quorum` tasks have
// succeeded, once every task has finished, or after `maxMs`, whichever comes
// first. Failed tasks just don't count.

export function firstAnswers<T>(
  tasks: readonly (() => Promise<T>)[],
  quorum: number,
  maxMs: number
): Promise<T[]> {
  return new Promise((resolve) => {
    const answers: T[] = [];
    let finished = 0;
    let done = false;
    const end = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve([...answers]);
    };
    const timer = setTimeout(end, maxMs);
    if (tasks.length === 0) return end();
    for (const task of tasks) {
      task().then(
        (answer) => {
          if (done) return;
          answers.push(answer);
          finished++;
          if (answers.length >= quorum || finished === tasks.length) end();
        },
        () => {
          if (done) return;
          finished++;
          if (finished === tasks.length) end();
        }
      );
    }
  });
}
