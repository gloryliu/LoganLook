package com.lzr;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.annotation.PreDestroy;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.Security;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.GZIPInputStream;

/**
 * @since logan-web 1.0
 */
public class LoganProtocol {

    private static final char ENCRYPT_CONTENT_START = '\1';
    private static final String AES_ALGORITHM_TYPE = "AES/CBC/NoPadding";
    private static AtomicBoolean initialized = new AtomicBoolean(false);

    static {
        initialize();
    }

    private ByteBuffer wrap;
    private FileOutputStream fileOutputStream;
    private String key = "";
    private String iv = "";

    public LoganProtocol(InputStream stream, File file, String key, String iv) throws IOException {
        wrap = ByteBuffer.wrap(IOUtils.toByteArray(stream));
        fileOutputStream = new FileOutputStream(file);
        this.key = key;
        this.iv = iv;
    }

    public boolean process() {
        while (wrap.hasRemaining()) {
            while (wrap.get() == ENCRYPT_CONTENT_START) {
                byte[] encrypt = new byte[wrap.getInt()];
                if (!tryGetEncryptContent(encrypt) || !decryptAndAppendFile(encrypt)) {
                    return false;
                }
            }
        }
        return true;
    }

    private boolean tryGetEncryptContent(byte[] encrypt) {
        try {
            wrap.get(encrypt);
        } catch (java.nio.BufferUnderflowException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    private boolean decryptAndAppendFile(byte[] encrypt) {
        boolean result = false;
        try {
            Cipher aesEncryptCipher = Cipher.getInstance(AES_ALGORITHM_TYPE);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "AES");
            aesEncryptCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv.getBytes()));
            byte[] compressed = aesEncryptCipher.doFinal(encrypt);
            byte[] plainText = decompress(compressed);
            result = true;
            fileOutputStream.write(plainText);
            fileOutputStream.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    private static byte[] decompress(byte[] contentBytes) {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            IOUtils.copy(new GZIPInputStream(new ByteArrayInputStream(contentBytes)), out);
            return out.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }

    @PreDestroy
    public void closeFileSteam() {
        try {
            fileOutputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * BouncyCastle作为安全提供，防止我们加密解密时候因为jdk内置的不支持改模式运行报错。
     **/
    private static void initialize() {
        if (initialized.get()) {
            return;
        }
        Security.addProvider(new BouncyCastleProvider());
        initialized.set(true);
    }

}