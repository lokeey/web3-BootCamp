import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

public class RSAPractice {

    public static void main(String[] args) throws Exception {
        System.out.println("=== RSA加密实践：生成密钥对、签名、验证和POW ===");

        // 1. 生成RSA公私钥对
        KeyPair keyPair = generateRSAKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        System.out.println("\n1. 生成的RSA密钥对：");
        System.out.println("私钥长度: " + privateKey.getModulus().bitLength() + " 位");
        System.out.println("公钥长度: " + publicKey.getModulus().bitLength() + " 位");
        System.out.println("公钥Base64: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        // 2. POW工作量证明：找到满足条件的nonce
        String nickname = "Practice";
        int powDifficulty = 4;
        System.out.println("\n2. 开始POW工作量证明（哈希值以" + powDifficulty + "个0开头）...");

        long nonce = performProofOfWorkParallel(nickname, powDifficulty);
        String message = nickname + nonce;
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        System.out.println("昵称: " + nickname);
        System.out.println("找到的Nonce: " + nonce);
        System.out.println("完整消息: " + message);
        System.out.println("哈希值: " + bytesToHex(sha256(messageBytes)));

        // 3. 用私钥对消息进行签名
        System.out.println("\n3. 使用私钥进行签名...");
        byte[] signature = signWithPrivateKey(messageBytes, privateKey);
        System.out.println("签名(Base64): " + Base64.getEncoder().encodeToString(signature));

        // 4. 用公钥验证签名
        System.out.println("\n4. 使用公钥验证签名...");
        boolean isValid = verifyWithPublicKey(messageBytes, signature, publicKey);
        System.out.println("签名验证结果: " + (isValid ? "✓ 验证成功" : "✗ 验证失败"));

        // 5. 验证篡改后的消息
        System.out.println("\n5. 测试篡改检测...");
        String tamperedMessage = nickname + (nonce + 1);
        byte[] tamperedBytes = tamperedMessage.getBytes(StandardCharsets.UTF_8);
        boolean isTamperedValid = verifyWithPublicKey(tamperedBytes, signature, publicKey);
        System.out.println("篡改后验证结果: " + (isTamperedValid ? "✗ 错误：应该失败" : "✓ 正确：检测到篡改"));

        // 6. 演示完整的密钥保存和加载过程
        System.out.println("\n6. 演示密钥序列化和反序列化...");
        String publicKeyStr = encodePublicKey(publicKey);
        String privateKeyStr = encodePrivateKey(privateKey);

        RSAPublicKey loadedPublicKey = decodePublicKey(publicKeyStr);
        RSAPrivateKey loadedPrivateKey = decodePrivateKey(privateKeyStr);

        // 用加载的密钥进行验证
        boolean verifyWithLoadedKey = verifyWithPublicKey(messageBytes, signature, loadedPublicKey);
        System.out.println("使用加载的公钥验证签名: " + (verifyWithLoadedKey ? "✓ 成功" : "✗ 失败"));
    }

    /**
     * 1. 生成RSA密钥对（2048位）
     */
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // 使用2048位密钥
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * 2. 执行工作量证明（POW） - 单线程版本（简单但慢）
     */
    public static long performProofOfWork(String nickname, int leadingZeros) {
        // 创建目标前缀字符串
        StringBuilder targetPrefixBuilder = new StringBuilder();
        for (int i = 0; i < leadingZeros; i++) {
            targetPrefixBuilder.append('0');
        }
        String targetPrefix = targetPrefixBuilder.toString();

        System.out.println("正在单线程寻找哈希值以 " + leadingZeros + " 个0开头的nonce...");
        long startTime = System.currentTimeMillis();

        for (long nonce = 1; nonce < Long.MAX_VALUE; nonce++) {
            String message = nickname + nonce;
            String hash = bytesToHex(sha256(message.getBytes(StandardCharsets.UTF_8)));

            if (hash.startsWith(targetPrefix)) {
                long endTime = System.currentTimeMillis();
                System.out.println("POW完成，耗时: " + (endTime - startTime) + "ms");
                return nonce;
            }

            // 每10万次输出一次进度
            if (nonce % 100000 == 0) {
                System.out.println("已尝试 " + nonce + " 个nonce值...");
            }
        }

        throw new RuntimeException("未找到符合条件的nonce");
    }

    /**
     * 2.1 执行工作量证明（POW） - 并行版本（推荐使用，更快）
     */
    public static long performProofOfWorkParallel(String nickname, int leadingZeros) {
        // 创建目标前缀字符串
        StringBuilder targetPrefixBuilder = new StringBuilder();
        for (int i = 0; i < leadingZeros; i++) {
            targetPrefixBuilder.append('0');
        }
        final String targetPrefix = targetPrefixBuilder.toString();

        System.out.println("正在并行寻找哈希值以 " + leadingZeros + " 个0开头的nonce...");
        long startTime = System.currentTimeMillis();

        // 使用固定线程池进行并行计算
        int processors = Runtime.getRuntime().availableProcessors();
        ExecutorService executor = Executors.newFixedThreadPool(processors);

        try {
            // 创建一个Future列表来收集结果
            List<Future<Long>> futures = new ArrayList<>();

            // 将搜索范围分成多个任务
            int tasks = processors * 4; // 每个处理器处理4个任务
            long rangeSize = 1000000; // 每个任务搜索100万个nonce

            for (int i = 0; i < tasks; i++) {
                final long start = i * rangeSize + 1;
                final long end = start + rangeSize;

                Callable<Long> task = new Callable<Long>() {
                    @Override
                    public Long call() {
                        for (long nonce = start; nonce < end; nonce++) {
                            String message = nickname + nonce;
                            String hash = bytesToHex(sha256(message.getBytes(StandardCharsets.UTF_8)));

                            if (hash.startsWith(targetPrefix)) {
                                return nonce;
                            }
                        }
                        return -1L; // 未找到
                    }
                };

                futures.add(executor.submit(task));
            }

            // 等待第一个找到的结果
            for (Future<Long> future : futures) {
                try {
                    Long result = future.get();
                    if (result != null && result > 0) {
                        long endTime = System.currentTimeMillis();
                        System.out.println("POW完成，耗时: " + (endTime - startTime) + "ms");
                        executor.shutdownNow(); // 停止其他任务
                        return result;
                    }
                } catch (InterruptedException | ExecutionException e) {
                    // 继续检查其他任务
                }
            }

        } finally {
            executor.shutdown();
        }

        throw new RuntimeException("未找到符合条件的nonce");
    }

    /**
     * 3. 使用私钥对消息进行签名
     */
    public static byte[] signWithPrivateKey(byte[] message, RSAPrivateKey privateKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // 使用SHA256withRSA算法
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message);
        return signature.sign();
    }

    /**
     * 4. 使用公钥验证签名
     */
    public static boolean verifyWithPublicKey(byte[] message, byte[] signatureBytes, RSAPublicKey publicKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(message);
        return signature.verify(signatureBytes);
    }

    /**
     * 计算SHA256哈希值
     */
    public static byte[] sha256(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 字节数组转十六进制字符串
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * 编码公钥为Base64字符串
     */
    public static String encodePublicKey(RSAPublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     * 编码私钥为Base64字符串
     */
    public static String encodePrivateKey(RSAPrivateKey privateKey) {
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    /**
     * 从Base64字符串解码公钥
     */
    public static RSAPublicKey decodePublicKey(String base64Key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) keyFactory.generatePublic(spec);
    }

    /**
     * 从Base64字符串解码私钥
     */
    public static RSAPrivateKey decodePrivateKey(String base64Key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) keyFactory.generatePrivate(spec);
    }

}
