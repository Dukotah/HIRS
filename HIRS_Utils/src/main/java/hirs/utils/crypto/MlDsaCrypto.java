package hirs.utils.crypto;

import hirs.utils.signature.cose.CoseAlgorithm;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.util.encoders.Base64;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.AsymmetricKey;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Locale;

/**
 * {@link CryptoEngine} for ML-DSA (FIPS 204) signatures, using the ML-DSA implementation built into
 * the JDK (JEP 497, Java 24 and later).
 * <p>
 * This engine is separate from {@link DefaultCrypto} so that the existing RSA and ECDSA paths are
 * unchanged. It handles the three FIPS 204 parameter sets, identified by their IANA registered COSE
 * algorithm names {@link CoseAlgorithm#ML_DSA_44}, {@link CoseAlgorithm#ML_DSA_65} and
 * {@link CoseAlgorithm#ML_DSA_87}. These names are also the JDK standard algorithm names.
 * <p>
 * ML-DSA signatures are a fixed-length byte string with no DER wrapping, so the bytes produced by
 * {@link #sign(byte[])} are placed into a COSE_Sign1 signature field as-is.
 * Only "pure" ML-DSA with an empty context string is supported (the COSE profile).
 */
public class MlDsaCrypto implements CryptoEngine {
    private static final String ML_DSA = "ML-DSA";
    private static final String PKCS8_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PKCS8_FOOTER = "-----END PRIVATE KEY-----";

    private PrivateKey privateKey = null;
    @Setter
    @Getter
    private PublicKey publicKey = null;
    @Getter
    private String algorithm = "";

    /**
     * Creates an engine with no key loaded. Use {@link #loadPrivateKey} before signing.
     */
    public MlDsaCrypto() {

    }

    /**
     * Creates an engine from an existing ML-DSA key pair.
     *
     * @param keyPair an ML-DSA key pair
     */
    public MlDsaCrypto(final KeyPair keyPair) {
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
        this.algorithm = parameterSetOf(keyPair.getPublic());
    }

    /**
     * Generates a new ML-DSA key pair for the given parameter set.
     *
     * @param coseAlg one of ML-DSA-44, ML-DSA-65 or ML-DSA-87
     * @return a new key pair
     * @throws GeneralSecurityException if the JDK does not provide ML-DSA
     */
    public static KeyPair generateKeyPair(final String coseAlg) throws GeneralSecurityException {
        requireMlDsa(coseAlg);
        return KeyPairGenerator.getInstance(coseAlg.toUpperCase(Locale.ROOT)).generateKeyPair();
    }

    /**
     * Loads a PKCS #8 PEM encoded ML-DSA private key.
     * The parameter set is taken from the key itself; if a certificate or algorithm name is supplied
     * it must name the same parameter set.
     *
     * @param pathToKey full file path to the private key to be loaded
     * @param cert optional certificate holding the matching public key; may be null
     * @param coseAlg optional COSE algorithm name; may be empty
     * @return true if the private key was successfully loaded
     */
    @Override
    public boolean loadPrivateKey(final String pathToKey, final X509Certificate cert,
                                  final String coseAlg) throws Exception {
        String pem = new String(Files.readAllBytes(new File(pathToKey).toPath()), StandardCharsets.UTF_8);
        if (!pem.contains(PKCS8_HEADER)) {
            throw new RuntimeException("ML-DSA private keys must be PKCS #8 PEM (" + PKCS8_HEADER + ")");
        }
        pem = pem.replace(PKCS8_HEADER, "").replace(PKCS8_FOOTER, "");
        PrivateKey key = KeyFactory.getInstance(ML_DSA)
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(pem)));
        String keyAlg = parameterSetOf(key);
        if (cert != null) {
            String certAlg = parameterSetOf(cert.getPublicKey());
            if (!certAlg.equals(keyAlg)) {
                throw new RuntimeException("Certificate key is " + certAlg + " but private key is " + keyAlg);
            }
            publicKey = cert.getPublicKey();
        }
        if (coseAlg != null && !coseAlg.isEmpty() && coseAlg.compareToIgnoreCase(keyAlg) != 0) {
            throw new RuntimeException("Requested algorithm " + coseAlg + " but private key is " + keyAlg);
        }
        privateKey = key;
        algorithm = keyAlg;
        return true;
    }

    /**
     * Signs the given data with the loaded ML-DSA private key.
     *
     * @param dataToSign data to be signed (for COSE, the Sig_structure)
     * @return the raw ML-DSA signature
     */
    @Override
    public byte[] sign(final byte[] dataToSign) throws Exception {
        if (privateKey == null) {
            throw new RuntimeException("No ML-DSA private key loaded");
        }
        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(privateKey);
        signature.update(dataToSign);
        return signature.sign();
    }

    /**
     * Verifies a raw ML-DSA signature.
     * The public key is taken from {@code pk} if given, otherwise from {@code cert}. If
     * {@code sigAlgorithm} is given it must match the parameter set of that key; a key of a different
     * parameter set is rejected rather than tried.
     *
     * @param cert an X.509 certificate holding an ML-DSA public key; may be null if pk is given
     * @param pk an ML-DSA public key; may be null if cert is given
     * @param sigAlgorithm optional COSE algorithm name; may be empty
     * @param data the data that was signed (for COSE, the Sig_structure)
     * @param signatureData the raw ML-DSA signature
     * @return true if the signature is valid; false otherwise, including a signature of the wrong
     * length for the key's parameter set
     */
    @Override
    public boolean verify(final X509Certificate cert, final PublicKey pk, final String sigAlgorithm,
                          final byte[] data, final byte[] signatureData) throws Exception {
        PublicKey key = pk;
        if (key == null && cert != null) {
            key = cert.getPublicKey();
        }
        if (key == null) {
            throw new RuntimeException("ML-DSA verification requires a certificate or public key");
        }
        String keyAlg = parameterSetOf(key);
        if (sigAlgorithm != null && !sigAlgorithm.isEmpty()) {
            requireMlDsa(sigAlgorithm);
            if (sigAlgorithm.compareToIgnoreCase(keyAlg) != 0) {
                return false;
            }
        }
        algorithm = keyAlg;
        Signature signature = Signature.getInstance(keyAlg);
        signature.initVerify(key);
        signature.update(data);
        try {
            return signature.verify(signatureData);
        } catch (SignatureException e) {
            // The JDK rejects a signature of the wrong length for the parameter set with an exception;
            // for the caller that is simply a signature that does not verify.
            return false;
        }
    }

    /**
     * Returns the ML-DSA parameter set name of a key, such as "ML-DSA-65".
     * Works for JDK keys (which report "ML-DSA" as their algorithm and carry the parameter set in
     * {@link AsymmetricKey#getParams()}) and for providers that report the parameter set directly.
     *
     * @param key an ML-DSA public or private key
     * @return the parameter set name, which is also the COSE algorithm name
     */
    public static String parameterSetOf(final Key key) {
        String name = key.getAlgorithm();
        if (CoseAlgorithm.isMlDsaName(name)) {
            return name.toUpperCase(Locale.ROOT);
        }
        if (key instanceof AsymmetricKey asymmetricKey) {
            AlgorithmParameterSpec params = asymmetricKey.getParams();
            if (params instanceof NamedParameterSpec named && CoseAlgorithm.isMlDsaName(named.getName())) {
                return named.getName().toUpperCase(Locale.ROOT);
            }
        }
        throw new RuntimeException("Not an ML-DSA key: " + name);
    }

    private static void requireMlDsa(final String coseAlg) {
        if (!CoseAlgorithm.isMlDsaName(coseAlg)) {
            throw new RuntimeException("Not an ML-DSA algorithm: " + coseAlg);
        }
    }
}
