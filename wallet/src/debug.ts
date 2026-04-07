/**
 * Debug Logger for the Wallet Application
 */
export class DebugLogger {
  private logElement: HTMLElement | null;
  private logs: string[] = [];

  constructor(elementId: string) {
    this.logElement = document.getElementById(elementId);
  }

  log(message: string, data?: unknown): void {
    const timestamp = new Date().toISOString().split("T")[1].split(".")[0];
    let logEntry = `[${timestamp}] ${message}`;
    
    if (data !== undefined) {
      logEntry += `\n${JSON.stringify(data, null, 2)}`;
    }
    
    this.logs.push(logEntry);
    console.log(message, data);
    
    this.updateDisplay();
  }

  error(message: string, error?: unknown): void {
    const timestamp = new Date().toISOString().split("T")[1].split(".")[0];
    let logEntry = `[${timestamp}] ❌ ERROR: ${message}`;
    
    if (error !== undefined) {
      if (error instanceof Error) {
        logEntry += `\n${error.message}\n${error.stack}`;
      } else {
        logEntry += `\n${JSON.stringify(error, null, 2)}`;
      }
    }
    
    this.logs.push(logEntry);
    console.error(message, error);
    
    this.updateDisplay();
  }

  success(message: string, data?: unknown): void {
    const timestamp = new Date().toISOString().split("T")[1].split(".")[0];
    let logEntry = `[${timestamp}] ✅ ${message}`;
    
    if (data !== undefined) {
      logEntry += `\n${JSON.stringify(data, null, 2)}`;
    }
    
    this.logs.push(logEntry);
    console.log(message, data);
    
    this.updateDisplay();
  }

  private updateDisplay(): void {
    if (this.logElement) {
      this.logElement.textContent = this.logs.slice(-50).join("\n\n");
      this.logElement.scrollTop = this.logElement.scrollHeight;
    }
  }

  clear(): void {
    this.logs = [];
    this.updateDisplay();
  }
}
