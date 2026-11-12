package org.ghulakh.app

/**
 * Waits for a recovery supervisor and the workers it registered to finish.
 * Interrupts are deferred until all workers have exited so session credentials
 * are not released while a replacement allocation is still using them.
 */
internal fun awaitWorkerTermination(
    supervisor: Thread?,
    workers: () -> List<Thread>,
) {
    val caller = Thread.currentThread()
    var interrupted = false

    fun join(thread: Thread) {
        if (thread === caller) return
        while (thread.isAlive) {
            try {
                thread.join()
            } catch (_: InterruptedException) {
                interrupted = true
            }
        }
    }

    try {
        supervisor?.let(::join)
        while (true) {
            val active = workers().filter { it !== caller && it.isAlive }
            if (active.isEmpty()) break
            active.forEach(::join)
        }
    } finally {
        if (interrupted) caller.interrupt()
    }
}
