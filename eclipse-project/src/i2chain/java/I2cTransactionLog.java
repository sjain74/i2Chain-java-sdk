package i2chain.java;

public class I2cTransactionLog {
	
	// The action performed on the document, e.g., Revoked, Shared, Chained, etc.
	String 	action;
	
	// The user who performed the action
	String 	by;

	// Document classification, e.g., Restricted, Confidential, Secret, Top Secret etc.
	String	classification;

	// The recipient
	String	recipient;

	// Status, e.g., Successful, Failed, Warning, etc.
	String	status;

	// Transaction date and time, e.g. 02-08-2021, 16:14; TBD: exact format to be described 
	String 	time;
}
