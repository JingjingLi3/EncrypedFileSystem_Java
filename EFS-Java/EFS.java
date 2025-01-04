import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Arrays;

public class EFS extends Utility {

    private static int macLength = 32;
    private static int userNameLength = 16;
//    private static int lengthStoreLength = 16;
//    private static int passwordHashLength = 32;

    public File dir;
    private static int blockSize = 16;

    public EFS() {}

    @Override
    public void create(String fileName, String userName, String password) throws Exception {
        dir = new File(fileName);

        dir.mkdirs();
        File meta = new File(dir, "0");
        byte[] toWrite = new byte[Config.BLOCK_SIZE];

        // 1. 256-bit MAC 0-255bit 0-31B
        // 2. 128-bit username 256-383bit 32-47B
        System.arraycopy(userName.getBytes(StandardCharsets.UTF_8), 0, toWrite, 32, userName.getBytes(StandardCharsets.UTF_8).length);

        // 3. 128-bit length of the file 384-511bit 48-63B
        int length = 0;
        byte[] lenghtByte = (length + "").getBytes(StandardCharsets.UTF_8);
        System.arraycopy(lenghtByte, 0, toWrite, 48, lenghtByte.length);

        // 4. 256-bit hash of password 512-767bit 64-95B
        System.arraycopy(Utility.hashSha256(password.getBytes(StandardCharsets.UTF_8)), 0, toWrite, 64, userName.getBytes(StandardCharsets.UTF_8).length);

        // encryption
        byte[] cipherText = blockEncryptCTR(password, (byte)0, toWrite);
        byte[] storeText = new byte[cipherText.length];
        System.arraycopy(toWrite, 0, storeText, 0, 48); // username plaintext
        System.arraycopy(cipherText, 48, storeText, 48, Config.BLOCK_SIZE-48);

        // calculate the hash value of ciphertext, except from the first 32B.
        byte[] hmac = hmacCalculator(Arrays.copyOfRange(storeText, 32, storeText.length), password);
        System.arraycopy(hmac, 0, storeText, 0, hmac.length);
        saveToFile(storeText, meta);

        // throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String findUser(String fileName) throws Exception {
        File file = new File(fileName);
        File meta = new File(file, "0");

        byte[] data = readFromFile(meta);
        byte[] userName = Arrays.copyOfRange(data, 32, 48);

        byte[] result = depadding(userName);

        return new String(result, StandardCharsets.UTF_8);

        //throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int length(String fileName, String password) throws Exception {
        File file = new File(fileName);
        File meta = new File(file, "0");

        byte[] cipherText = readFromFile(meta);
        byte[] plainText = blockDecryptCTR(password, (byte)0, cipherText);

        byte[] length = Arrays.copyOfRange(plainText, 48, 64);
        byte[] result = depadding(length);

        return Integer.parseInt(new String(result, StandardCharsets.UTF_8));
        //throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] read(String fileName, int sPos, int len, String password) throws Exception {

        File root = new File(fileName);
        int file_length = length(fileName, password);

        if (sPos + len > file_length) {
            throw new Exception();
        }


        // start file and end file to read
        int start_block = sPos / Config.BLOCK_SIZE;
        int end_block = (sPos + len) / Config.BLOCK_SIZE;

        byte[] toReturn = new byte[len];
        int contentLen = 0;
        byte[] page = new byte[Config.BLOCK_SIZE];
        for (int i = start_block + 1; i <= end_block + 1; i++) {
            byte[] temp = readFromFile(new File(root, Integer.toString(i)));
            temp = blockDecryptCTR(password, (byte)0, temp);
            System.arraycopy(temp, 0, page, 0, Config.BLOCK_SIZE);

            if (i == end_block + 1) {
                page = getSubBytes(page, 0, (sPos + len) % Config.BLOCK_SIZE);
            }
            if(i == start_block + 1) {
                page = getSubBytes(page, sPos % Config.BLOCK_SIZE, page.length - sPos % Config.BLOCK_SIZE);
            }
            System.arraycopy(page, 0, toReturn, contentLen, page.length);
            contentLen += page.length;
        }

        return toReturn;
//        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void write(String fileName, int sPos, byte[] content, String password) throws Exception {
//        throw new UnsupportedOperationException("Not supported yet.");
        File root = new File(fileName);
        int file_length = length(fileName, password);

        if (sPos > file_length) {
            throw new Exception();
        }

        // content length and blocks.
        int len = content.length;
        int start_block = sPos / Config.BLOCK_SIZE;
        int end_block = (sPos + len) / Config.BLOCK_SIZE;

        // write to each block file.
        for (int i = start_block + 1; i <= end_block + 1; i++) {

            int sp = (i - 1) * Config.BLOCK_SIZE - sPos;  // if sPos is in the middle of a file, sp will be negative, the length do not change.
            int ep = (i) * Config.BLOCK_SIZE - sPos;  // the length of content need to be modified in the file.

            byte[] prefix = new byte[Config.BLOCK_SIZE];
            byte[] postfix = new byte[Config.BLOCK_SIZE];
            if (i == start_block + 1 && sPos != start_block * Config.BLOCK_SIZE) {  // not start from 0 byte.
                prefix = readFromFile(new File(root, Integer.toString(i)));
                prefix = blockDecryptCTR(password, (byte)0, prefix);
                prefix = Arrays.copyOfRange(prefix, 0, sPos % Config.BLOCK_SIZE);
                sp = Math.max(sp, 0);  // get prefix, so change sp to 0.
            }

            if (i == end_block + 1) {
                File end = new File(root, Integer.toString(i));
                if (end.exists()) {

                    postfix = readFromFile(new File(root, Integer.toString(i)));
                    postfix = blockDecryptCTR(password, (byte)0, postfix);

                    if (postfix.length > sPos + len - end_block * Config.BLOCK_SIZE) {   // if not end at the last byte.
                        postfix = Arrays.copyOfRange(postfix, sPos + len - end_block * Config.BLOCK_SIZE, Config.BLOCK_SIZE);
                    } else {
                        postfix = new byte[]{0};
                    }

                }
                ep = Math.min(ep, len);
            }

            prefix = depadding(prefix);
            postfix = depadding(postfix);

//            byte[] toWrite = new byte[prefix.length + (ep-sp) + postfix.length];
            byte[] toWrite = new byte[Config.BLOCK_SIZE];
            System.arraycopy(prefix, 0, toWrite, 0, prefix.length);
            byte[] JJL = Arrays.copyOfRange(content, sp, ep);

            System.arraycopy(JJL, 0, toWrite, prefix.length, JJL.length);

            System.arraycopy(postfix, 0, toWrite, prefix.length + JJL.length, postfix.length);

            toWrite = blockEncryptCTR(password, (byte)0, toWrite);
            saveToFile(toWrite, new File(root, Integer.toString(i)));
        }

        /*
        update metadata
        if length changes, modify both length and mac, if length does not change, modify only mac
         */

        // copy old data except from HMAC
        byte[] metaData = readFromFile(new File(root, "0"));
        byte[] plainText = blockDecryptCTR(password, (byte)0, metaData);
        byte[] toWrite = new byte[Config.BLOCK_SIZE];
        System.arraycopy(plainText, macLength, toWrite, macLength, Config.BLOCK_SIZE-macLength);

        int newLength = length(fileName, password);
        // modify length in new metadata.
        if (len + sPos > length(fileName, password)) {
            newLength = len + sPos;
            byte[] lengthByte = (newLength + "").getBytes(StandardCharsets.UTF_8);
            System.arraycopy(lengthByte, 0, toWrite, macLength+userNameLength, lengthByte.length);
        }

        // encrypt metadata to compute mac
        byte[] cipherMeta = blockEncryptCTR(password, (byte)0, toWrite);
        System.arraycopy(cipherMeta, macLength+userNameLength, toWrite, macLength+userNameLength, cipherMeta.length-(macLength+userNameLength));

        // need to write the file first to change the length feature.
        saveToFile(toWrite, new File(root, "0"));

        // get whole content and metadata
        byte[] fileWholeContent = read(fileName, 0, newLength, password);  // read will call length to get corrent length, while the new length has not been write to the file.
        byte[] storeText = new byte[fileWholeContent.length + Config.BLOCK_SIZE - macLength];

        // compute MAC.
        System.arraycopy(toWrite, macLength, storeText, 0, Config.BLOCK_SIZE - macLength);
        System.arraycopy(fileWholeContent, 0, storeText, Config.BLOCK_SIZE - macLength, fileWholeContent.length);
        byte[] hmac = hmacCalculator(storeText, password);
        System.arraycopy(hmac, 0, toWrite, 0, hmac.length);

        saveToFile(toWrite, new File(root, "0"));
    }

    @Override
    public boolean checkIntegrity(String fileName, String password) throws Exception {
        File root = new File(fileName);
        int contentLength = length(fileName, password);
        if(contentLength == 0){
            File meta = new File(root, "0" );
            byte[] cipherText = readFromFile(meta);
            byte[] hmac = hmacCalculator(Arrays.copyOfRange(cipherText, 32, cipherText.length), password);
            byte[] storedHmac = Arrays.copyOfRange(cipherText, 0, hmac.length);
            if(Arrays.equals(hmac, storedHmac)){
                return true;
            }
        }else {
            int newLength = length(fileName, password);

            // get whole content and metadata
            byte[] fileWholeContent = read(fileName, 0, newLength, password);  // read will call length to get corrent length, while the new length has not been write to the file.
            byte[] storeText = new byte[fileWholeContent.length + Config.BLOCK_SIZE - macLength];

            // read metadata
            byte[] metaData = readFromFile(new File(root, "0"));
            System.arraycopy(metaData, macLength, storeText, 0, Config.BLOCK_SIZE - macLength);
            System.arraycopy(fileWholeContent, 0, storeText, Config.BLOCK_SIZE - macLength, fileWholeContent.length);
            byte[] hmac = hmacCalculator(storeText, password);
            byte[] oldMac = Arrays.copyOfRange(metaData, 0, 16);
            String hmacStr = new String(hmac, StandardCharsets.UTF_8);
            System.out.println(hmacStr);
            String oldMacStr = new String(oldMac, StandardCharsets.UTF_8);
            System.out.println(oldMacStr);
            return hmacStr.equals(oldMacStr);
        }
        return false;


//        throw new UnsupportedOperationException("Not supported yet.");
    }


    // --------------all encapsulated functions used in about methods------------------
    private byte[] depadding(byte[] inputs) {
        int last_index = inputs.length - 1;
        while (last_index >= 0 && inputs[last_index] == 0) {
            last_index--;
        }
        if (last_index == -1) {
            return new byte[0];
        }

        // Create a new array with length equal to the last non-zero byte index + 1
        byte[] depad_inputs = new byte[last_index + 1];
        System.arraycopy(inputs, 0, depad_inputs, 0, last_index + 1);
        return depad_inputs;
    }

    private byte[] keyGeneratorCTR(String password, byte fileBlockNum) throws Exception {
        byte[] bytes = Arrays.copyOfRange(hashSha256((password+fileBlockNum).getBytes(StandardCharsets.UTF_8)), 0, 16);
        return bytes;
    }

    private byte[] nonceGeneratorCTR(String password) throws Exception {
        byte[] bytes = Arrays.copyOfRange(hashSha256(password.getBytes()),0, 15);
        return bytes;
    }

    private byte[] xorCalculator(byte[] array1, byte[] array2) {
        if (array1.length != array2.length) {
            throw new IllegalArgumentException("Arrays must have the same length for XOR operation.");
        }

        byte[] result = new byte[array1.length];

        for (int i = 0; i < array1.length; i++) {
            result[i] = (byte) (array1[i] ^ array2[i]);
        }

        return result;
    }

    private byte[] bytePadding(byte[] origin, int byteLength){
        byte[] bytes = new byte[byteLength];
        Arrays.copyOfRange(origin, 0, origin.length);
        return bytes;
    }

    // first generate IV and nonce, ctr = 64*filenumber + startpos/128.
    // first calculate the key from password, and the Nonce from password and then call AES to
    private byte[] blockEncryptCTR(String password, byte fileBlockNum, byte[] fileBlockContent) throws Exception {

        byte chunckSize = 16; // bytes
        byte blockNum = 64;
        byte ctrBase = (byte) (fileBlockNum*blockNum); // no matter if it overflows

        byte[] plainText = fileBlockContent;
        byte[] cipherText = new byte[Config.BLOCK_SIZE];

        byte[] key = keyGeneratorCTR(password, fileBlockNum);
        byte[] nonce = nonceGeneratorCTR(password);
        byte[] plainAes = new byte[chunckSize];

        while(plainText.length != Config.BLOCK_SIZE) {
            plainText = bytePadding(plainText, Config.BLOCK_SIZE);
        }

        // Encryption
        for (byte i = 0; i < blockNum; i++) {
            System.arraycopy(nonce, 0, plainAes, 0, nonce.length);
            plainAes[chunckSize-1] = (byte)(i+ctrBase);
            byte[] xorText = encryptAes(plainAes, key);
//            System.out.println("888888888" + Arrays.toString(xorText) + ":" + xorText.length);
            byte[] cipher = xorCalculator(xorText, Arrays.copyOfRange(plainText, i*chunckSize, (i+1)*chunckSize));
            System.arraycopy(cipher, 0, cipherText, blockSize*i, xorText.length);
        }
        return cipherText;
    }

    // decryption
    private byte[] blockDecryptCTR(String password, byte fileBlockNum, byte[] fileBlockContent) throws Exception {
        byte chunckSize = 16; // bytes
        byte blockNum = 64;
        byte ctrBase = (byte) (fileBlockNum*blockNum); // no matter if it overflows

        byte[] cipherText = fileBlockContent;
        byte[] plainText = new byte[Config.BLOCK_SIZE];

        byte[] key = keyGeneratorCTR(password, fileBlockNum);
        byte[] nonce = nonceGeneratorCTR(password);
        byte[] plainAes = new byte[chunckSize];

        // Decryption
        for (byte i = 0; i < blockNum; i++) {
            System.arraycopy(nonce, 0, plainAes, 0, nonce.length);
            plainAes[chunckSize-1] = (byte)(i+ctrBase);
            byte[] xorText = encryptAes(plainAes, key);
            byte[] plain = xorCalculator(xorText, Arrays.copyOfRange(cipherText, i*chunckSize, (i+1)*chunckSize));
            System.arraycopy(plain, 0, plainText, blockSize*i, xorText.length);
        }
        return plainText;
    }


    //HMAC
    private byte[] keyGeneratorMac(String password, boolean type) throws Exception {
        //type 0: IV, type 1: key
        if(type){
            return Arrays.copyOfRange(hashSha384(password.getBytes(StandardCharsets.UTF_8)), 16, 32);
        }else {
            return Arrays.copyOfRange(hashSha512(password.getBytes(StandardCharsets.UTF_8)), 16, 32);
        }
    }

    /*
    For HMAC,we use CBC-MAC, we first generate IV and key from password, and then XOR it with plaintext block,
    and then do hash funciton to encrypt them. Store the last ciphertext block as the MAC of entire text.
     */
    private byte[] hmacCalculator(byte[] wholeContent, String password) throws Exception {
        byte chunckSize = 16;
        byte[] plainText = wholeContent;

        // padding
        if (wholeContent.length % chunckSize != 0) {
            plainText = new byte[(wholeContent.length / chunckSize + 1) * chunckSize];
            System.arraycopy(wholeContent, 0, plainText, 0, wholeContent.length);
        }

        // generate iv and key
        byte[] iv = keyGeneratorMac(password, false);
        byte[] hashKey = keyGeneratorMac(password, true);

        // CBC
        int blockNum = plainText.length / chunckSize;
        byte[] hashValue = iv;

        for (byte i = 0; i < blockNum; i++) {
            // plaintext block xor iv(or cipher of last round)
            byte[] toXorPlain = Arrays.copyOfRange(plainText, i*chunckSize, (i+1)*chunckSize);
            byte[] xoredText = xorCalculator(toXorPlain, hashValue);

            // combine xored result and key.
            byte[] toHashPlain = new byte[chunckSize+hashKey.length];
            System.arraycopy(xoredText, 0, toHashPlain, 0, xoredText.length);
            System.arraycopy(hashKey, 0, toHashPlain, xoredText.length, hashKey.length);

            // hash function
            byte[] hash = hashSha256(toHashPlain);
            hashValue = Arrays.copyOfRange(hash, 0, chunckSize);
        }

        return hashValue;
    }

    private byte[] getSubBytes(byte[] inputs, int start, int length) {
        // Check if start and length are valid
        if (start < 0 || length < 0 || start + length > inputs.length) {
            throw new IllegalArgumentException("Invalid start or length parameters.");
        }
        byte[] subset = new byte[length];
        System.arraycopy(inputs, start, subset, 0, length);
        return subset;
    }
}
