package i2chain.java;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient; 
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;

import org.apache.hc.core5.http.HttpStatus; 

public class I2cAPIs {
    
    private final String API_SERVER                         = "https://api.i2chain.com/";
    private final String API_KEY_VALUE                      = "kLNWDrGhpCUVxqtK7jypmtCoPLYqDyNg";
    
    private final String END_POINT_LOGIN                    = "auth/v2/login";
    private final String END_POINT_GENERATE_DATA_KEY        = "file/generate/datakey";
    private final String END_POINT_LOGOUT                   = "auth/logout";
    
    private final String HEADER_CONTENT_TYPE                = "Content-Type";
    private final String HEADER_API_KEY                     = "x-api-key";
    private final String HEADER_AUTHORIZATION               = "Authorization";
    private final String HEADER_APPLICATION_JSON            = "application/json";
    
    private final String TAG_EMAIL                          = "email";
    private final String TAG_PASSWORD                       = "password";
    private final String TAG_TOKEN                          = "token";
    private final String TAG_ID_TOKEN                       = "idToken";
    private final String TAG_JWT_TOKEN                      = "jwtToken";
    private final String TAG_DATA                           = "data";
    private final String TAG_PLAIN_TEXT_DATA_KEY            = "plaintextDataKey";
    private final String TAG_FILE_INFO_DOC_ID               = "docID";
    private final String TAG_FILE_INFO_CHECKSUM             = "checksum";
    private final String TAG_FILE_INFO_TYPE                 = "type";
    private final String TAG_FILE_INFO_FILE_NAME            = "fileName";
    
    private final String ENCRYPTION_ALGORITHM               = "AES/CBC/PKCS5Padding";
    private final String CHECKSUM_SHA1                      = "SHA1";
    
    private final String FILE_INFO_FILE_NAME                = "info.json";
    private final String ENC_FILE_EXTENSION                 = ".ch";
    private final String I2C_FILE_EXTENSION                 = ".i2c";
    
    private final String ERR_MSG_CLIENT_SEND_LOGIN          = "Sending Login HTTP request failed.";
    private final String ERR_MSG_CLIENT_SEND_LOGOUT         = "Sending Logout HTTP request failed.";
    private final String ERR_MSG_CLIENT_SEND_GEN_DATA_KEY   = "Sending Generate Data Key HTTP request failed.";
    private final String ERR_MSG_FILE_ENCRYPTION            = "File encryption failed.";
    private final String ERR_MSG_CHECKSUM                   = "File checksum computation failed.";
    private final String ERR_MSG_ARCHIVE_FILE_CREATION      = "Archive/i2c file creation failed.";
    private final String ERR_MSG_INFO_FILE_CREATION         = "info.json file creation failed.";
    
    //  
    // i2c_getAuthToken 
    // 
    //    SDK function provided by i2Chain to login a user and get the auth token. 
    // 
    // Return value: 
    //         True for success 
    //        False for a failure. In this case errorResponse contains the details about the error. 
    //

    public Boolean i2c_getAuthToken (String             userName,        // Input
                                     String             password,        // Input
                                     StringBuilder      authToken,       // Output
                                     I2cStatusResponse  statusResponse)  // Output

    {
        System.out.println("i2c_getAuthToken"); 
        
        HttpClient client = HttpClient.newHttpClient();

        JSONObject payloadObj = new JSONObject(); 
        payloadObj.put(TAG_EMAIL, userName);
        payloadObj.put(TAG_PASSWORD, password);

        HttpRequest request = HttpRequest.newBuilder(URI.create(API_SERVER + END_POINT_LOGIN))
                                         .header(HEADER_CONTENT_TYPE, HEADER_APPLICATION_JSON)
                                         .header(HEADER_API_KEY, API_KEY_VALUE)
                                         .POST(BodyPublishers.ofString(payloadObj.toString()))
                                         .build();

        try
        {
            HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
            
            if ((statusResponse.status = response.statusCode()) == HttpStatus.SC_OK)
            {
                System.out.println("response: " + response.body()); 
                JSONObject jsonResponse = new JSONObject(response.body());
                authToken.append(jsonResponse.getJSONObject(TAG_TOKEN).getJSONObject(TAG_ID_TOKEN).getString(TAG_JWT_TOKEN));
                return true;
            } else 
            {
                return false;
            }
        } catch (Exception e)
        {
            e.printStackTrace();
            statusResponse.status = HttpStatus.SC_METHOD_FAILURE;
            statusResponse.description = ERR_MSG_CLIENT_SEND_LOGIN;
            return false;
        }
    } 
    
    //  
    // i2c_ createAWebLink 
    // 
    //    SDK function provided by i2Chain to create a weblink for a given i2c file.  
    // 
    // Return value: 
    //         True for success 
    //        False for a failure. In this case errorResponse contains the details about the error. 
    //

    public Boolean i2c_createAWebLink (String               authToken,       // Input
                                       String               filePath,        // Input
                                       String               classification,  // Input
                                       StringBuilder        docId,           // Output
                                       StringBuilder        webLink,         // Output
                                       I2cStatusResponse    statusResponse)  // Output

    {
        // use i2Chain REST API to create a weblink for a given i2c file
        
        // for each file:
            // generate docID, get encryption key, create i2C file, call save chain data REST API
        
        // call createWeblink REST API with a thread ID.
        
        // if all good, return True, else build errorResponse and return False
        
        String i2cFilePath = filePath;
        
        if (_classifyAndChain(authToken, filePath, classification, i2cFilePath, docId, statusResponse)) {
            
        }
        
        return true;

    }
    
    //  
    // i2c_recordSharing
    // 
    //    SDK function provided by i2Chain to record, in the i2Chain backend, sharing of a document with one or more recipients 
    // 
    // Return value: 
    //         True for success 
    //        False for a failure. In this case errorResponse contains the details about the error. 
    //

    public Boolean i2c_recordSharing (String            authToken,        // Input
                                      Byte[]            docId,            // Input
                                      String[]          recipients,       // Output
                                      I2cStatusResponse statusResponse)   // Output

    {
        // use i2Chain REST API to record sharing of the docId with the recipients
        // if all good, return True, else build errorResponse and return False
        
        return true;

    }
    
    //  
    // i2c_recordSharing
    // 
    //    SDK function provided by i2Chain to fetch transaction logs from the i2Chain backend. 
    // 
    // Return value: 
    //         True for success 
    //        False for a failure. In this case errorResponse contains the details about the error. 
    //

    public Boolean i2c_getTransactionLogs (String                 authToken,            // Input
                                           String                 by,                   // Input
                                           String                 docId,                // Input
                                           String                 recipient,            // Input
                                           String                 fromDate,             // Input
                                           String                 toDate,               // Input
                                           String                 classification,       // Input
                                           I2cTransactionLog[]    transactionLogs,      // Output
                                           I2cStatusResponse      statusResponse)       // Output

    {
        //         At least one of “by”, “docId”, and “recipient” should be specified 
        //         A filter is constructed by ANDing the parameters that are specified, e.g., 
        //             - return all the transaction logs where by=john@cb.com AND docId=123xyz456 
        //                AND recipient=tom@equifax.com 
        //             - return all the transaction logs where by=john@smith.com AND  
        //                docId=123xyz456 
        //             - return all the transaction logs where docId=123xyz456  
        // 
        //         The transaction logs are returned in transactionLogs array from latest to oldest order 
        // 
        //         It is made sure that the authenticated user (authToken) has access to the logs that are  
        //         returned in the result set. I.e. even if some transaction logs satisfy the filter they may  
        //        not appear in the result set if the caller of this function does not have access to those  
        //        transaction logs. 
        
        // if all good, return True, else build errorResponse and return False
        
        return true;

    } 

 
    //  
    // i2c_logout
    // 
    //    SDK function provided by i2Chain to logout a user from the i2Chain backend. 
    // 
    // Return value: 
    //         True for success 
    //        False for a failure. In this case errorResponse contains the details about the error. 
    //

    public Boolean i2c_logout (String                authToken,        // Input
                               I2cStatusResponse     statusResponse)   // Output 

    { 
        System.out.println("i2c_logout");
        
        HttpClient client = HttpClient.newHttpClient();

        HttpRequest request = HttpRequest.newBuilder(URI.create(API_SERVER + END_POINT_LOGOUT))
                                         .header(HEADER_CONTENT_TYPE, HEADER_APPLICATION_JSON)
                                         .header(HEADER_AUTHORIZATION, authToken)
                                         .POST(BodyPublishers.noBody())
                                         .build();

        try
        {
            HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
            
            if ((statusResponse.status = response.statusCode()) == HttpStatus.SC_OK)
            {
                System.out.println("response: " + response.body()); 
                return true;
            } else 
            {
                return false;
            }
        } catch (Exception e)
        {
            e.printStackTrace();
            statusResponse.status = HttpStatus.SC_METHOD_FAILURE;
            statusResponse.description = ERR_MSG_CLIENT_SEND_LOGOUT;
            return false;
        }
    }
    
    //  
    // _classifyAndChain 
    // 
    //    A private function to classify and chain a document, i.e. convert it to an i2c file (archive).  
    // 
    // Return value: 
    //         True for success 
    //        False for a failure. In this case errorResponse contains the details about the error. 
    //

    private Boolean _classifyAndChain (String                 authToken,       // Input
                                       String                 filePath,        // Input
                                       String                 classification,  // Input
                                       String                 i2cFilePath,     // Input
                                       StringBuilder          docId,           // Output
                                       I2cStatusResponse      statusResponse)  // Output

    {
        System.out.println("_classifyAndChain");
        
        StringBuilder plaintextDataKey = new StringBuilder();
        if (! _getPlaintextDataKey(authToken, plaintextDataKey, statusResponse)) 
        {
            return false;
        }
        
        File origFile = new File(filePath);
        File chFile = new File(i2cFilePath + "/" + origFile.getName() + ENC_FILE_EXTENSION);
        File infoFile = new File(i2cFilePath + "/" + FILE_INFO_FILE_NAME);
        File i2cFile = new File(i2cFilePath + "/" + origFile.getName() + I2C_FILE_EXTENSION);
        
        // cleanup any previous files
        chFile.delete();
        infoFile.delete();
        i2cFile.delete();
        
        if (! _encryptFile(plaintextDataKey.toString(), origFile, chFile, statusResponse))
        {
            return false;
        }
        
        if (! _createInfoJsonFile(origFile, infoFile, docId, statusResponse))
        {
            return false;
        }
        
        try 
        {
            List<String> srcFiles = Arrays.asList(chFile.getPath(), infoFile.getPath());
            FileOutputStream fos = new FileOutputStream(i2cFilePath + "/" + origFile.getName() + I2C_FILE_EXTENSION);
            ZipOutputStream zipOut = new ZipOutputStream(fos);
            for (String srcFile : srcFiles)
            {
                File fileToZip = new File(srcFile);
                FileInputStream fis = new FileInputStream(fileToZip);
                ZipEntry zipEntry = new ZipEntry(fileToZip.getName());
                zipOut.putNextEntry(zipEntry);
    
                byte[] bytes = new byte[1024];
                int length;
                while((length = fis.read(bytes)) >= 0)
                {
                    zipOut.write(bytes, 0, length);
                }
                fis.close();
            }
            zipOut.close();
            fos.close();
        } catch (Exception e)
        {
            e.printStackTrace();
            statusResponse.status = HttpStatus.SC_METHOD_FAILURE;
            statusResponse.description = ERR_MSG_ARCHIVE_FILE_CREATION;
            return false;
        }
        
        return true;
    }
    
    //  
    // _getPlaintextDataKey 
    // 
    //    A private function to get a plain text data key from i2Chain backend.  
    // 
    // Return value: 
    //         True for success 
    //        False for a failure. In this case errorResponse contains the details about the error. 
    //
    
    private Boolean _getPlaintextDataKey(String             authToken,           // Input
                                         StringBuilder      plaintextDataKey,    // Output
                                         I2cStatusResponse  statusResponse)      // Output
    {
        System.out.println("_getPlaintextDataKey");
        
        HttpClient client     = HttpClient.newHttpClient();
        HttpRequest request   = HttpRequest.newBuilder(URI.create(API_SERVER + END_POINT_GENERATE_DATA_KEY))
                                           .header(HEADER_AUTHORIZATION, authToken)
                                           .POST(BodyPublishers.noBody())
                                           .build();
        
        try
        {
            HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
            
            if ((statusResponse.status = response.statusCode()) == HttpStatus.SC_OK)
            {
                System.out.println("response: " + response.body());
                JSONObject jsonResponse = new JSONObject(response.body());
                plaintextDataKey.append(jsonResponse.getJSONObject(TAG_DATA).getString(TAG_PLAIN_TEXT_DATA_KEY));
            } else 
            {
                return false;
            }
        } catch (Exception e)
        {
            e.printStackTrace();
            statusResponse.status = HttpStatus.SC_METHOD_FAILURE;
            statusResponse.description = ERR_MSG_CLIENT_SEND_GEN_DATA_KEY;
            return false;
        }
        return true;
    }
    
    //  
    // _encryptFile 
    // 
    //    A private function to encrypt a file.   
    //
    
    private Boolean _encryptFile(String               plaintextDataKey,    // Input
                                 File                 inputFile,           // Input
                                 File                 outputFile,          // Input
                                 I2cStatusResponse    statusResponse)      // Output
    {
        System.out.println("_encryptFile");
        
        String             algorithm   = ENCRYPTION_ALGORITHM;
        IvParameterSpec    iv          = _generateIv();
        byte[]             keyData     = Base64.getDecoder().decode(plaintextDataKey);
        SecretKey          key         = new SecretKeySpec(keyData, 0, keyData.length, "AES"); 
        
        try
        {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            FileInputStream inputStream = new FileInputStream(inputFile);
            FileOutputStream outputStream = new FileOutputStream(outputFile);
            byte[] buffer = new byte[64];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1)
            {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null)
                {
                    outputStream.write(output);
                }
            }
            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null)
            {
                outputStream.write(outputBytes);
            }
            inputStream.close();
            outputStream.close();
        } catch (Exception e)
        {
            e.printStackTrace();
            statusResponse.status = HttpStatus.SC_METHOD_FAILURE;
            statusResponse.description = ERR_MSG_FILE_ENCRYPTION;
            return false;
        }
        return true;
    }
    
    //  
    // _generateIv 
    // 
    //    A private function to generate an IV (Initialization Vector) used in initializing a Cipher.   
    //
    
    private IvParameterSpec _generateIv()
    {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
    
    //  
    // _createSha1Checksum 
    // 
    //    A private function to create a SHA-1 checksum/message-digest of a file.   
    //
    
    private Boolean _createSha1Checksum(File               origFile,        // Input
                                        StringBuilder      checksum,        // Output
                                        I2cStatusResponse  statusResponse)  // Output
    {
        System.out.println("_createSha1Checksum");
        
        try 
        {
            MessageDigest messageDigest = MessageDigest.getInstance(CHECKSUM_SHA1);
            
            FileInputStream fileInput = new FileInputStream(origFile.getPath());
            byte[] dataBytes = new byte[1024];
     
            int bytesRead = 0;
     
            while ((bytesRead = fileInput.read(dataBytes)) != -1) {
                messageDigest.update(dataBytes, 0, bytesRead);
            }
             
            byte[] digestBytes = messageDigest.digest();
             
            for (int i = 0; i < digestBytes.length; i++) {
                checksum.append(Integer.toString((digestBytes[i] & 0xff) + 0x100, 16).substring(1));
            }
     
            System.out.println("Checksum for the File: " + checksum.toString());
            fileInput.close();
        } catch (Exception e) 
        {
            e.printStackTrace();
            statusResponse.status = HttpStatus.SC_METHOD_FAILURE;
            statusResponse.description = ERR_MSG_CHECKSUM;
            return false;
        }
        return true;
    }
    
    //  
    // _createInfoJsonFile 
    // 
    //    A private function to create info.json file in temporary archive folder.  
    // 
    // Return value: 
    //         True for success 
    //        False for a failure. In this case errorResponse contains the details about the error. 
    //
    
    private Boolean _createInfoJsonFile(File                origFile,        // Input
                                        File                infoFile,        // Input
                                        StringBuilder       docId,           // Output
                                        I2cStatusResponse   statusResponse)  // Output
    {
        System.out.println("_createInfoJsonFile");
        
        docId.append(UUID.randomUUID().toString());
        JSONObject fileInfo = new JSONObject();
        fileInfo.put(TAG_FILE_INFO_DOC_ID, docId);
        String fileName = origFile.getName();
        fileInfo.put(TAG_FILE_INFO_TYPE, fileName.substring(fileName.lastIndexOf('.') + 1));
        fileInfo.put(TAG_FILE_INFO_FILE_NAME, fileName + ENC_FILE_EXTENSION);
        
        StringBuilder checksum = new StringBuilder();
        if (! _createSha1Checksum(origFile, checksum, statusResponse))
        {
            return false;
        }
        fileInfo.put(TAG_FILE_INFO_CHECKSUM, checksum.toString()); 
        
        try
        {
            if (infoFile.createNewFile())
            {
                System.out.println("File created: " + infoFile.getName());
            } else
            {
                System.out.println("Issue in creating file: " + infoFile.getName());
                statusResponse.status = HttpStatus.SC_METHOD_FAILURE;
                statusResponse.description = ERR_MSG_INFO_FILE_CREATION;
                return false;
            }
            
            FileWriter myWriter = new FileWriter(infoFile.getPath());
            myWriter.write(fileInfo.toString());
            myWriter.close();
            System.out.println("Successfully wrote to info.json: " + fileInfo.toString());
        } catch (IOException e)
        {
            System.out.println("An error occurred while creating file:" + infoFile.getName());
            e.printStackTrace();
            statusResponse.status = HttpStatus.SC_METHOD_FAILURE;
            statusResponse.description = ERR_MSG_INFO_FILE_CREATION;
            return false;
        }
        
        return true;
    }
    
    public static void main(String[] args)
    {
        I2cAPIs             i2cAPIs         = new I2cAPIs();
        StringBuilder       authToken       = new StringBuilder();
        I2cStatusResponse   statusResponse  = null;
        String              userName        = "amtbht11@gmail.com";
        String              password        = "Hello@123";
        
        statusResponse    = new I2cStatusResponse();
        
        if (i2cAPIs.i2c_getAuthToken(userName, password, authToken, statusResponse)) 
        {
            System.out.println("i2c_getAuthToken SUCCEEDED");
            System.out.println("statusResponse: " + statusResponse.status);
            System.out.println("authToken: " + authToken);
        } else
        {
            System.out.println("i2c_getAuthToken FAILED");
            System.out.println("statusResponse: " + statusResponse.status);
            return;
        }
        
        System.out.println();
        
        StringBuilder docId = new StringBuilder();
        if (i2cAPIs._classifyAndChain (authToken.toString(), "/Users/sanjain/Downloads/sanjay_jain_resume.pdf", 
                                        "Confidential", "/Users/sanjain/Downloads", docId, statusResponse))
        {
            System.out.println("_classifyAndChain SUCCEEDED");
            System.out.println("statusResponse: " + statusResponse.status);
            System.out.println("docId: " + docId);
        } else 
        {
            System.out.println("_classifyAndChain FAILED");
            System.out.println("statusResponse: " + statusResponse.status);
        }
        
        System.out.println();
        
        if (i2cAPIs.i2c_logout(authToken.toString(), statusResponse)) 
        {
            System.out.println("i2c_logout SUCCEEDED");
            System.out.println("statusResponse: " + statusResponse.status);
        } else
        {
            System.out.println("i2c_logout FAILED");
            System.out.println("statusResponse: " + statusResponse.status);
            return;
        }
    }
}
