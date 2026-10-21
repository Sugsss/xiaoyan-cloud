import com.android.apksig.ApkSigner;

import java.io.File;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 小燕 App 重签名工具（基于 Google apksig 官方引擎）。
 * 用法: java -cp apksig.jar SignTool <input.apk> <output.apk> <keystore> <storepass> <alias> [keypass]
 */
public class SignTool {
    public static void main(String[] args) throws Exception {
        if (args.length < 5) {
            System.err.println("用法: java -cp apksig.jar SignTool <in.apk> <out.apk> <keystore> <storepass> <alias> [keypass]");
            System.exit(2);
        }
        String inApk = args[0], outApk = args[1], ksPath = args[2], ksPass = args[3], alias = args[4];
        String keyPass = args.length > 5 ? args[5] : ksPass;

        KeyStore ks = KeyStore.getInstance(new File(ksPath), ksPass.toCharArray());
        PrivateKey key = (PrivateKey) ks.getKey(alias, keyPass.toCharArray());
        if (key == null) {
            throw new IllegalArgumentException("keystore 中找不到别名 " + alias + " 的私钥");
        }
        Certificate[] chain = ks.getCertificateChain(alias);
        if (chain == null || chain.length == 0) {
            throw new IllegalArgumentException("keystore 中找不到别名 " + alias + " 的证书链");
        }
        List<X509Certificate> certs = new ArrayList<>();
        for (Certificate c : chain) {
            certs.add((X509Certificate) c);
        }

        ApkSigner.SignerConfig config =
                new ApkSigner.SignerConfig.Builder(alias, key, certs).build();
        ApkSigner signer = new ApkSigner.Builder(Collections.singletonList(config))
                .setInputApk(new File(inApk))
                .setOutputApk(new File(outApk))
                .setV1SigningEnabled(true)   // JAR 签名，兼容 Android 5.x/6.x (minSdk 21)
                .setV2SigningEnabled(true)   // APK 签名块，Android 7.0+
                .setV3SigningEnabled(true)   // APK 签名块 v3，Android 9.0+
                .setMinSdkVersion(21)
                .setCreatedBy("xiaoyan-patch")
                .build();
        signer.sign();
        System.out.println("SIGNED OK -> " + outApk);
    }
}
