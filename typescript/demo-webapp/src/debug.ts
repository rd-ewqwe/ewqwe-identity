/**
 * Debug Logger for the Relying Party Application
 */
export class DebugLogger {
  private logs: Array<{ timestamp: string; level: string; message: string; data?: unknown }> = [];

  log(message: string, data?: unknown): void {
    const entry = {
      timestamp: new Date().toISOString(),
      level: "info",
      message,
      data,
    };
    this.logs.push(entry);
    console.log(`[INFO] ${message}`, data);
  }

  error(message: string, error?: unknown): void {
    const entry = {
      timestamp: new Date().toISOString(),
      level: "error",
      message,
      data: error instanceof Error ? { message: error.message, stack: error.stack } : error,
    };
    this.logs.push(entry);
    console.error(`[ERROR] ${message}`, error);
  }

  success(message: string, data?: unknown): void {
    const entry = {
      timestamp: new Date().toISOString(),
      level: "success",
      message,
      data,
    };
    this.logs.push(entry);
    console.log(`[SUCCESS] ${message}`, data);
  }

  getLogs(): typeof this.logs {
    return this.logs;
  }

  getFormattedLogs(): string {
    return this.logs
      .map((log) => {
        let str = `[${log.timestamp}] [${log.level.toUpperCase()}] ${log.message}`;
        if (log.data) {
          str += `\n${JSON.stringify(log.data, null, 2)}`;
        }
        return str;
      })
      .join("\n\n");
  }

  clear(): void {
    this.logs = [];
  }
}
