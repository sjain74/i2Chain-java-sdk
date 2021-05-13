package i2chain.java;

public class I2cTransactionLog {
    
    // The action performed on the document, e.g., Revoked, Shared, Chained, etc.
    String      action;
    String      by;
    String      recipient;
    Boolean     success;
    String      failedReason;
    String      time;
    
    public void debugPrint()
    {
        System.out.println("action: " + action);
        System.out.println("by: " + by);
        System.out.println("recipient: " + recipient);
        System.out.println("success: " + success);
        System.out.println("failedReason: " + failedReason);
        System.out.println("time: " + time);
    }
}
