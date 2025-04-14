class Logger {
    constructor() {
      this.subscribers = [];
    }
  
    subscribe(subscriber) {
      this.subscribers.push(subscriber);
    }
  
    log(action, user, details) {
      const timestamp = new Date().toISOString();
      const logMessage = `[${timestamp}] ${action} by ${user || 'system'}: ${details}`;
      
      this.subscribers.forEach(subscriber => subscriber(logMessage));
    }
  }
  
  module.exports = new Logger();