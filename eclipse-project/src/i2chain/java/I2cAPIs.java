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
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Encoder;
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
    
    private final String API_SERVER                             = "https://api.i2chain.com/";
    private final String API_KEY_VALUE                          = "kLNWDrGhpCUVxqtK7jypmtCoPLYqDyNg";
    
    private final String END_POINT_LOGIN                        = "auth/v2/login";
    private final String END_POINT_GENERATE_DATA_KEY            = "file/generate/datakey";
    private final String END_POINT_LOGOUT                       = "auth/logout";
    private final String END_POINT_GENERATE_WEBLINK_ID          = "file/generate/threadId";
    private final String END_POINT_SAVE_CHAIN_DATA              = "file/saveChainData";
    private final String END_POINT_GET_TXN_LOGS                 = "transaction/getAllList";
    
    private final String HEADER_CONTENT_TYPE                    = "Content-Type";
    private final String HEADER_API_KEY                         = "x-api-key";
    private final String HEADER_AUTHORIZATION                   = "Authorization";
    private final String HEADER_APPLICATION_JSON                = "application/json";
    
    private final String TAG_EMAIL                              = "email";
    private final String TAG_PASSWORD                           = "password";
    private final String TAG_TOKEN                              = "token";
    private final String TAG_ID_TOKEN                           = "idToken";
    private final String TAG_JWT_TOKEN                          = "jwtToken";
    private final String TAG_DATA                               = "data";
    private final String TAG_PLAIN_TEXT_DATA_KEY                = "plaintextDataKey";
    private final String TAG_DOC_ID                             = "docId";
    private final String TAG_CHECKSUM                           = "checksum";
    private final String TAG_TYPE                               = "type";
    private final String TAG_FILE_NAME                          = "fileName";
    private final String TAG_WEBLINK_ID                         = "threadId";
    private final String TAG_USER_ID                            = "userId";
    private final String TAG_FILE_ID                            = "fileId";
    private final String TAG_FILE_SIZE                          = "fileSize";
    private final String TAG_FILE_BUFFER                        = "fileBuffer";
    private final String TAG_FILE_PATH                          = "filePath";
    private final String TAG_MIME_TYPE                          = "mimeType";
    private final String TAG_LOCATION                           = "location";
    private final String TAG_CIPHER_TEXT                        = "ciphertext";
    private final String TAG_CIPHER_TEXT_DATA_KEY               = "cipherTextDataKey";
    private final String TAG_FILE_TYPE                          = "fileType";
    private final String TAG_CLASSIFICATION_ID                  = "classificationId";
    
    private final String ENCRYPTION_ALGORITHM                   = "AES/CBC/PKCS5Padding";
    private final String CHECKSUM_SHA1                          = "SHA1";
    
    private final String FILE_INFO_FILE_NAME                    = "info.json";
    private final String ENC_FILE_EXTENSION                     = ".ch";
    private final String I2C_FILE_EXTENSION                     = ".i2c";
    
    private final String EM_CLIENT_SEND_LOGIN                   = "Sending Login HTTP request failed.";
    private final String EM_CLIENT_SEND_LOGOUT                  = "Sending Logout HTTP request failed.";
    private final String EM_CLIENT_SEND_GEN_DATA_KEY            = "Sending Generate Data Key HTTP request failed.";
    private final String EM_CLIENT_SEND_GEN_WEBLINK_ID          = "Sending Generate Weblink ID HTTP request failed.";
    private final String EM_CLIENT_SEND_SAVE_CHAIN_DATA         = "Sending Save Chain Data HTTP request failed.";
    private final String EM_CLIENT_SEND_GET_TXN_LOGS            = "Sending Get Transaction Logs HTTP request failed.";
    
    private final String EM_FILE_ENCRYPTION                     = "File encryption failed.";
    private final String EM_CHECKSUM                            = "File checksum computation failed.";
    private final String EM_ARCHIVE_FILE_CREATION               = "Archive/i2c file creation failed.";
    private final String EM_INFO_FILE_CREATION                  = "info.json file creation failed.";
    private final String EM_CWL_INVALID_COMBINATION_OF_ARGS     = "Length of files, classifications, and docIds arrays does not match";
    private final String EM_READ_ALL_I2C_FILE_BYTES             = "Reading i2c file in memory buffer failed";
    
    /**  
     * i2c_getAuthToken 
     * 
     * SDK function provided by i2Chain to login as a user and get an authentication token.
     *     
     * Return value: 
     *    True for success 
     *    False for a failure. In this case errorResponse contains the details about the error. 
     */

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
            statusResponse.description = EM_CLIENT_SEND_LOGIN;
            return false;
        }
    } 
    
    /**  
     * i2c_createWebLink 
     * 
     * SDK function provided by i2Chain to create a weblink for a set of attachments files that are shared as i2c files. 
     *     
     * Return value: 
     *    True for success 
     *    False for a failure. In this case errorResponse contains the details about the error. 
     */

    public Boolean i2c_classifyAndChain (String               authToken,       // Input
                                         String[]             filePaths,       // Input
                                         String[]             classifications, // Input
                                         String               i2cFilePath,     // Input
                                         StringBuilder[]      docIds,          // Output
                                         I2cStatusResponse    statusResponse)  // Output

    {
        System.out.println("i2c_createWebLink"); 
        
        if ((filePaths.length != classifications.length) || (filePaths.length != docIds.length))
        {
            statusResponse.status = HttpStatus.SC_BAD_REQUEST;
            statusResponse.description = EM_CWL_INVALID_COMBINATION_OF_ARGS;
            return false;
        }
        
        JSONObject chainData = new JSONObject();
        
        for (int i=0; i<filePaths.length; i++)
        {
            if (! _classifyAndChain(authToken, filePaths[i], classifications[i], i2cFilePath, chainData, statusResponse))
            {
                return false;
            }
            docIds[i].append(chainData.getString(TAG_DOC_ID));
            
            if (! _saveChainData(authToken, chainData, statusResponse))
            {
                return false;
            }
        }
        
        return true;

    }
    
    /**  
     * i2c_recordSharing 
     * 
     * SDK function provided by i2Chain to record, in the i2Chain backend, sharing of a document with one or more recipients 
     *     
     * Return value: 
     *    True for success 
     *    False for a failure. In this case errorResponse contains the details about the error. 
     */

    public Boolean i2c_recordSharing (String            authToken,        // Input
                                      String            threadId,          // Input
                                      String[]          recipients,       // Output
                                      I2cStatusResponse statusResponse)   // Output

    {
        // use i2Chain REST API to record sharing of the docId with the recipients
        // if all good, return True, else build errorResponse and return False
        
        /* StringBuilder weblinkId = new StringBuilder();
        StringBuilder userId = new StringBuilder();
        
        if (! _getUserWeblinkId(authToken, userId, weblinkId, statusResponse))
        {
            return false;
        } */
        
        return true;

    }
    
    /**  
     * i2c_getTransactionLogs 
     * 
     * SDK function provided by i2Chain to fetch transaction logs from the i2Chain backend. 
     *     
     * Return value: 
     *    True for success 
     *    False for a failure. In this case errorResponse contains the details about the error. 
     */

    public Boolean i2c_getTransactionLogs (String                   authToken,            // Input
                                           String                   by,                   // Input
                                           String                   docId,                // Input
                                           String                   recipient,            // Input
                                           String                   fromDate,             // Input
                                           String                   toDate,               // Input
                                           String                   classification,       // Input
                                           List<I2cTransactionLog>  transactionLogs,      // Output
                                           I2cStatusResponse        statusResponse)       // Output

    {
        System.out.println("i2c_getTransactionLogs");
        
        HttpClient client = HttpClient.newHttpClient();
        String uriString = API_SERVER + END_POINT_GET_TXN_LOGS;
        if (docId != null)
        {
            uriString += "?docId=" + docId;
        }
        HttpRequest request = HttpRequest.newBuilder(URI.create(uriString))
                                         .header(HEADER_AUTHORIZATION, authToken)
                                         .GET()
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
            statusResponse.description = EM_CLIENT_SEND_GET_TXN_LOGS;
            return false;
        }

    } 
    
    /**  
     * i2c_logout 
     * 
     * SDK function provided by i2Chain to logout a user from the i2Chain backend.
     *     
     * Return value: 
     *    True for success 
     *    False for a failure. In this case errorResponse contains the details about the error. 
     */

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
            statusResponse.description = EM_CLIENT_SEND_LOGOUT;
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
                                       JSONObject             chainData,       // Output
                                       I2cStatusResponse      statusResponse)  // Output

    {   
        System.out.println("_classifyAndChain");
        
        StringBuilder plaintextDataKey = new StringBuilder();
        if (! _getPlaintextDataKey(authToken, plaintextDataKey, chainData, statusResponse)) 
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
        
        if (! _createInfoJsonFile(origFile, infoFile, chainData, statusResponse))
        {
            return false;
        }
        
        try 
        {
            List<String> srcFiles = Arrays.asList(chFile.getPath(), infoFile.getPath());
            FileOutputStream fos = new FileOutputStream(i2cFile.getPath());
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
            statusResponse.description = EM_ARCHIVE_FILE_CREATION;
            return false;
        }
        
        chainData.put(TAG_FILE_ID, i2cFile.getParent());
        chainData.put(TAG_FILE_NAME, i2cFile.getName());
        
        try {
            byte[] fileBuffer;
            fileBuffer = Files.readAllBytes(i2cFile.toPath());
            Encoder encoder = Base64.getEncoder();
            String base64EncFile = encoder.encodeToString(fileBuffer);
            chainData.put(TAG_FILE_SIZE, base64EncFile.length());
            chainData.put(TAG_FILE_BUFFER, base64EncFile);
            chainData.put(TAG_FILE_PATH, i2cFile.getParent());
            String fileExt = filePath.substring(filePath.lastIndexOf('.') + 1); 
            chainData.put(TAG_MIME_TYPE, fileExt);
            chainData.put(TAG_LOCATION, "local");
            chainData.put(TAG_FILE_TYPE, fileExt);
            chainData.put(TAG_CLASSIFICATION_ID, "5f60722c640fe94dbd7fca66"); // TODO: classification
        } catch (IOException e) {
            e.printStackTrace();
            statusResponse.status = HttpStatus.SC_METHOD_FAILURE;
            statusResponse.description = EM_READ_ALL_I2C_FILE_BYTES;
            return false;
        }
        
        System.out.println("chainData.TAG_CIPHER_TEXT: " + chainData.getJSONArray(TAG_CIPHER_TEXT));
        System.out.println("chainData.TAG_FILE_ID: " + chainData.getString(TAG_FILE_ID));
        System.out.println("chainData.TAG_FILE_NAME: " + chainData.getString(TAG_FILE_NAME));
        System.out.println("chainData.TAG_FILE_BUFFER: " + "<file buffer>");
        System.out.println("chainData.TAG_FILE_SIZE: " + chainData.getInt(TAG_FILE_SIZE));
        System.out.println("chainData.TAG_FILE_PATH: " + chainData.getString(TAG_FILE_PATH));
        System.out.println("chainData.TAG_MIME_TYPE: " + chainData.getString(TAG_MIME_TYPE));
        System.out.println("chainData.TAG_LOCATION: " + chainData.getString(TAG_LOCATION));
        System.out.println("chainData.TAG_FILE_TYPE: " + chainData.getString(TAG_FILE_TYPE));
        System.out.println("chainData.TAG_CLASSIFICATION_ID: " + chainData.getString(TAG_CLASSIFICATION_ID));
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
                                         JSONObject         chainData,           // Output
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
                chainData.put(TAG_CIPHER_TEXT, jsonResponse.getJSONObject(TAG_DATA)
                                                           .getJSONObject(TAG_CIPHER_TEXT_DATA_KEY)
                                                           .getJSONArray(TAG_DATA));
            } else 
            {
                return false;
            }
        } catch (Exception e)
        {
            e.printStackTrace();
            statusResponse.status = HttpStatus.SC_METHOD_FAILURE;
            statusResponse.description = EM_CLIENT_SEND_GEN_DATA_KEY;
            return false;
        }
        return true;
    }
    
    //  
    // _getAWeblinkID 
    // 
    //    A private function to get a weblink ID from the i2Chain backend.  
    // 
    // Return value: 
    //         True for success 
    //        False for a failure. In this case errorResponse contains the details about the error. 
    //
    
    private Boolean _getUserWeblinkId(String             authToken,        // Input
                                      StringBuilder      userId,           // Output
                                      StringBuilder      weblinkId,        // Output
                                      I2cStatusResponse  statusResponse)   // Output
    {
        System.out.println("_getUserWeblinkId");
        
        HttpClient client     = HttpClient.newHttpClient();
        HttpRequest request   = HttpRequest.newBuilder(URI.create(API_SERVER + END_POINT_GENERATE_WEBLINK_ID))
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
                userId.append(jsonResponse.getJSONObject(TAG_DATA).getString(TAG_USER_ID));
                weblinkId.append(jsonResponse.getJSONObject(TAG_DATA).getString(TAG_WEBLINK_ID));
            } else 
            {
                return false;
            }
        } catch (Exception e)
        {
            e.printStackTrace();
            statusResponse.status = HttpStatus.SC_METHOD_FAILURE;
            statusResponse.description = EM_CLIENT_SEND_GEN_WEBLINK_ID;
            return false;
        }
        return true;
    }
    
    //  
    // _saveChainData 
    // 
    //    A private function to save chain data, associated with an i2c file, in the i2Chain backend.  
    // 
    // Return value: 
    //         True for success 
    //        False for a failure. In this case errorResponse contains the details about the error. 
    //
    
    private Boolean _saveChainData(String               authToken,      // Input
                                   JSONObject           chainData,      // Input
                                   I2cStatusResponse    statusResponse) // Output
    {
        System.out.println("_saveChainData");
        
        HttpClient client     = HttpClient.newHttpClient();
        HttpRequest request   = HttpRequest.newBuilder(URI.create(API_SERVER + END_POINT_SAVE_CHAIN_DATA))
                                           .header(HEADER_AUTHORIZATION, authToken)
                                           .header(HEADER_CONTENT_TYPE, HEADER_APPLICATION_JSON)
                                           .POST(BodyPublishers.ofString(chainData.toString()))
                                           .build();
        
        try
        {
            HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
            
            if ((statusResponse.status = response.statusCode()) == HttpStatus.SC_OK)
            {
                System.out.println("response: " + response.body());
                JSONObject jsonResponse = new JSONObject(response.body());
            } else 
            {
                return false;
            }
        } catch (Exception e)
        {
            e.printStackTrace();
            statusResponse.status = HttpStatus.SC_METHOD_FAILURE;
            statusResponse.description = EM_CLIENT_SEND_SAVE_CHAIN_DATA;
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
            statusResponse.description = EM_FILE_ENCRYPTION;
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
            statusResponse.description = EM_CHECKSUM;
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
                                        JSONObject          chainData,       // Output
                                        I2cStatusResponse   statusResponse)  // Output
    {
        System.out.println("_createInfoJsonFile");
        
        chainData.put(TAG_DOC_ID, UUID.randomUUID().toString());
        JSONObject fileInfo = new JSONObject();
        fileInfo.put(TAG_DOC_ID, chainData.getString(TAG_DOC_ID));
        String fileName = origFile.getName();
        fileInfo.put(TAG_TYPE, fileName.substring(fileName.lastIndexOf('.') + 1));
        fileInfo.put(TAG_FILE_NAME, fileName + ENC_FILE_EXTENSION);
        
        StringBuilder checksum = new StringBuilder();
        if (! _createSha1Checksum(origFile, checksum, statusResponse))
        {
            return false;
        }
        fileInfo.put(TAG_CHECKSUM, checksum.toString()); 
        chainData.put(TAG_CHECKSUM, checksum.toString()); 
        
        try
        {
            if (infoFile.createNewFile())
            {
                System.out.println("File created: " + infoFile.getName());
            } else
            {
                System.out.println("Issue in creating file: " + infoFile.getName());
                statusResponse.status = HttpStatus.SC_METHOD_FAILURE;
                statusResponse.description = EM_INFO_FILE_CREATION;
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
            statusResponse.description = EM_INFO_FILE_CREATION;
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
            
        String[] filePaths = {"/Users/sanjain/Downloads/sanjay_jain_resume.pdf"};
        String[] classifications = {"Secret"};
        StringBuilder[] docIds = {new StringBuilder()};
        
        if (i2cAPIs.i2c_classifyAndChain (authToken.toString(), filePaths, classifications, "/Users/sanjain/Downloads",
                                          docIds, statusResponse))
        {
            System.out.println("i2c_createWebLink SUCCEEDED");
            System.out.println("statusResponse: " + statusResponse.status);
            System.out.println("docId: " + docIds[0]);
        } else 
        {
            System.out.println("i2c_createWebLink FAILED");
            System.out.println("statusResponse: " + statusResponse.status);
        }
        
        System.out.println();
        
        ArrayList<I2cTransactionLog> txnLogs = new ArrayList<>();
        if (i2cAPIs.i2c_getTransactionLogs (authToken.toString(), null, docIds[0].toString(), null, null, null,
                                            null, txnLogs, statusResponse))
        {
            System.out.println("i2c_getTransactionLogs SUCCEEDED");
            System.out.println("statusResponse: " + statusResponse.status);
            System.out.println("docId: " + docIds[0]);
        } else 
        {
            System.out.println("i2c_getTransactionLogs FAILED");
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
