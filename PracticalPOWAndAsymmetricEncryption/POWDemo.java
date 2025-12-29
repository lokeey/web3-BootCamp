import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

public class POWDemo {

    public static void main(String[] args) {
        // 使用昵称
        String nickname = "POWDemo";

        System.out.println("开始POW计算...");
        System.out.println("昵称: " + nickname);
        printSeparator(60);

        // 任务1: 计算4个0开头的哈希值
        System.out.println("任务1: 寻找4个前导0的哈希值");
        POWResult result4 = findHashWithZeros(nickname, 4);
        printResult(result4, 4);

        printSeparator(60);

        // 任务2: 计算5个0开头的哈希值
        System.out.println("任务2: 寻找5个前导0的哈希值");
        POWResult result5 = findHashWithZeros(nickname, 5);
        printResult(result5, 5);
    }

    /**
     * POW结果类
     */
    private static class POWResult {
        final long nonce;
        final String content;
        final String hash;
        final long attempts;
        final Duration duration;

        POWResult(long nonce, String content, String hash, long attempts, Duration duration) {
            this.nonce = nonce;
            this.content = content;
            this.hash = hash;
            this.attempts = attempts;
            this.duration = duration;
        }
    }

    /**
     * 查找满足指定数量前导0的哈希值
     */
    private static POWResult findHashWithZeros(String nickname, int leadingZeros) {
        String targetPrefix = createPrefix(leadingZeros);
        Instant startTime = Instant.now();
        AtomicLong attempts = new AtomicLong(0);

        long nonce = 0;
        while (true) {
            attempts.incrementAndGet();
            String content = nickname + nonce;
            String hash = sha256(content);

            if (hash.startsWith(targetPrefix)) {
                Instant endTime = Instant.now();
                Duration duration = Duration.between(startTime, endTime);
                return new POWResult(nonce, content, hash, attempts.get(), duration);
            }

            nonce++;

            // 显示进度
            if (attempts.get() % 500000 == 0) {
                System.out.print(".");
            }
        }
    }

    /**
     * 创建前导0字符串
     */
    private static String createPrefix(int leadingZeros) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < leadingZeros; i++) {
            sb.append('0');
        }
        return sb.toString();
    }

    /**
     * 打印分隔线
     */
    private static void printSeparator(int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append('=');
        }
        System.out.println(sb.toString());
    }

    /**
     * 计算SHA256哈希值
     */
    private static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes("UTF-8"));
            return bytesToHex(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 字节数组转十六进制字符串
     */
    private static String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789abcdef".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = hexArray[v >>> 4];
            hexChars[i * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * 打印结果
     */
    private static void printResult(POWResult result, int leadingZeros) {
        System.out.println("\n" + createSeparator(40));
        System.out.println("成功找到 " + leadingZeros + " 个前导0的哈希值!");
        System.out.println("耗时: " + formatTime(result.duration));
        System.out.println("尝试次数: " + formatNumber(result.attempts));
        System.out.println("Nonce值: " + result.nonce);
        System.out.println("原始内容: " + result.content);
        System.out.println("SHA256哈希值: " + result.hash);

        // 计算哈希速率
        double seconds = result.duration.toMillis() / 1000.0;
        double hashesPerSecond = result.attempts / seconds;
        System.out.println("哈希速率: " + formatDecimal(hashesPerSecond) + " H/s");
        System.out.println(createSeparator(40));
    }

    /**
     * 创建分隔线字符串
     */
    private static String createSeparator(int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append('=');
        }
        return sb.toString();
    }

    /**
     * 格式化时间
     */
    private static String formatTime(Duration duration) {
        long minutes = duration.toMinutes();
        long seconds = duration.getSeconds() % 60;
        long millis = duration.toMillis() % 1000;

        if (minutes > 0) {
            return String.format("%d分%d.%03d秒", minutes, seconds, millis);
        } else {
            return String.format("%d.%03d秒", seconds, millis);
        }
    }

    /**
     * 格式化数字（添加千位分隔符）
     */
    private static String formatNumber(long number) {
        // Java 8中简单的千位分隔符格式化
        return String.format("%,d", number);
    }

    /**
     * 格式化小数
     */
    private static String formatDecimal(double number) {
        return String.format("%,.0f", number);
    }
}
