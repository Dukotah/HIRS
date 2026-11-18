package hirs.utils.crypto;

import hirs.utils.signature.cose.CoseAlgorithm;
import hirs.utils.signature.cose.CoseSignature;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link MlDsaCrypto}: ML-DSA (FIPS 204) signing and verification of COSE_Sign1
 * structures built by {@link CoseSignature}, as used for TCG Component RIMs and CoRIMs.
 */
public class MlDsaCryptoTest {
    private static final String[] PARAMETER_SETS = {
            CoseAlgorithm.ML_DSA_44, CoseAlgorithm.ML_DSA_65, CoseAlgorithm.ML_DSA_87};
    private static final int[] COSE_IDS = {-48, -49, -50};
    // Signature sizes in bytes from FIPS 204, Table 2
    private static final int[] SIGNATURE_SIZES = {2420, 3309, 4627};
    private static final byte[] PAYLOAD = "HIRS ML-DSA COSE_Sign1 test payload".getBytes(StandardCharsets.UTF_8);
    private static final byte[] KID = "11".getBytes(StandardCharsets.UTF_8);
    private static final int PEM_LINE_LENGTH = 64;
    private static final long ONE_DAY_MS = 86_400_000L;

    /**
     * Checks the COSE algorithm registrations and that generated keys report their parameter set.
     */
    @Test
    public final void testParameterSets() throws Exception {
        for (int i = 0; i < PARAMETER_SETS.length; i++) {
            assertEquals(COSE_IDS[i], CoseAlgorithm.getAlgId(PARAMETER_SETS[i]));
            assertEquals(PARAMETER_SETS[i], CoseAlgorithm.getAlgName(COSE_IDS[i]));
            assertTrue(CoseAlgorithm.isMlDsa(COSE_IDS[i]));
            assertFalse(CoseAlgorithm.isEcdsa(COSE_IDS[i]));
            assertFalse(CoseAlgorithm.isRsa(COSE_IDS[i]));

            KeyPair keyPair = MlDsaCrypto.generateKeyPair(PARAMETER_SETS[i]);
            assertEquals(PARAMETER_SETS[i], MlDsaCrypto.parameterSetOf(keyPair.getPublic()));
            assertEquals(PARAMETER_SETS[i], MlDsaCrypto.parameterSetOf(keyPair.getPrivate()));
        }
        assertFalse(CoseAlgorithm.isMlDsa(CoseAlgorithm.COSE_ES_SHA_256));
        assertFalse(CoseAlgorithm.isMlDsaName(CoseAlgorithm.ECDSA_SHA256));
        assertThrows(RuntimeException.class, () -> MlDsaCrypto.generateKeyPair(CoseAlgorithm.ECDSA_SHA256));
    }

    /**
     * Signs a COSE_Sign1 with each ML-DSA parameter set, encodes it, parses it back and verifies it.
     */
    @Test
    public final void testCoseSign1RoundTrip() throws Exception {
        for (int i = 0; i < PARAMETER_SETS.length; i++) {
            KeyPair keyPair = MlDsaCrypto.generateKeyPair(PARAMETER_SETS[i]);
            MlDsaCrypto signer = new MlDsaCrypto(keyPair);

            CoseSignature coseSig = new CoseSignature();
            byte[] toBeSigned = coseSig.createToBeSigned(CoseAlgorithm.getAlgId(PARAMETER_SETS[i]),
                    KID, PAYLOAD, null, true, false, "test");
            byte[] signature = signer.sign(toBeSigned);
            assertEquals(SIGNATURE_SIZES[i], signature.length);
            coseSig.addSignature(signature);
            byte[] signedCose = coseSig.getSignedData();

            CoseSignature parsed = new CoseSignature();
            byte[] toBeVerified = parsed.getToBeVerified(signedCose);
            assertArrayEquals(toBeSigned, toBeVerified);
            assertEquals(COSE_IDS[i], parsed.getAlgId());
            assertArrayEquals(signature, parsed.getSignature());

            String alg = CoseAlgorithm.getAlgName(parsed.getAlgId());
            MlDsaCrypto verifier = new MlDsaCrypto();
            assertTrue(verifier.verify(null, keyPair.getPublic(), alg, toBeVerified, parsed.getSignature()));

            byte[] tampered = toBeVerified.clone();
            tampered[tampered.length - 1] ^= 1;
            assertFalse(verifier.verify(null, keyPair.getPublic(), alg, tampered, parsed.getSignature()));
        }
    }

    /**
     * A signature must not verify under a key of another parameter set, or when the COSE header
     * names a different parameter set than the key.
     */
    @Test
    public final void testParameterSetMismatch() throws Exception {
        KeyPair key44 = MlDsaCrypto.generateKeyPair(CoseAlgorithm.ML_DSA_44);
        KeyPair key65 = MlDsaCrypto.generateKeyPair(CoseAlgorithm.ML_DSA_65);
        byte[] signature = new MlDsaCrypto(key44).sign(PAYLOAD);

        MlDsaCrypto verifier = new MlDsaCrypto();
        assertTrue(verifier.verify(null, key44.getPublic(), "", PAYLOAD, signature));
        assertFalse(verifier.verify(null, key44.getPublic(), CoseAlgorithm.ML_DSA_65, PAYLOAD, signature));
        assertFalse(verifier.verify(null, key65.getPublic(), "", PAYLOAD, signature));
        assertThrows(RuntimeException.class,
                () -> verifier.verify(null, key44.getPublic(), CoseAlgorithm.ECDSA_SHA256, PAYLOAD, signature));
    }

    /**
     * Loads a PKCS #8 PEM ML-DSA private key from disk, signs, and verifies.
     *
     * @param tempDir JUnit temporary directory for the key file
     */
    @Test
    public final void testLoadPemPrivateKey(@TempDir final Path tempDir) throws Exception {
        KeyPair keyPair = MlDsaCrypto.generateKeyPair(CoseAlgorithm.ML_DSA_87);
        Path keyFile = tempDir.resolve("mldsa87.key");
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(PEM_LINE_LENGTH, "\n".getBytes(StandardCharsets.US_ASCII))
                        .encodeToString(keyPair.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
        Files.writeString(keyFile, pem);

        MlDsaCrypto signer = new MlDsaCrypto();
        assertTrue(signer.loadPrivateKey(keyFile.toString(), null, ""));
        assertEquals(CoseAlgorithm.ML_DSA_87, signer.getAlgorithm());
        byte[] signature = signer.sign(PAYLOAD);

        assertTrue(new MlDsaCrypto().verify(null, keyPair.getPublic(), "", PAYLOAD, signature));
        assertThrows(RuntimeException.class,
                () -> new MlDsaCrypto().loadPrivateKey(keyFile.toString(), null, CoseAlgorithm.ML_DSA_44));
    }

    /**
     * Embeds an ML-DSA-65 signing certificate in the COSE_Sign1 protected header (RFC 9360 x5chain and
     * x5t), takes the kid from its Subject Key Identifier, and verifies using the certificate recovered
     * from the parsed structure.
     */
    @Test
    public final void testEmbeddedMlDsaCertificate() throws Exception {
        KeyPair keyPair = MlDsaCrypto.generateKeyPair(CoseAlgorithm.ML_DSA_65);
        X509Certificate cert = selfSignedCert(keyPair, CoseAlgorithm.ML_DSA_65);
        assertEquals(CoseAlgorithm.ML_DSA_65, MlDsaCrypto.parameterSetOf(cert.getPublicKey()));

        CoseSignature coseSig = new CoseSignature();
        byte[] toBeSigned = coseSig.createToBeSigned(CoseAlgorithm.COSE_ML_DSA_65, new byte[0], PAYLOAD,
                cert, false, true, "test");
        coseSig.addSignature(new MlDsaCrypto(keyPair).sign(toBeSigned));
        byte[] signedCose = coseSig.getSignedData();

        CoseSignature parsed = new CoseSignature();
        byte[] toBeVerified = parsed.getToBeVerified(signedCose);
        X509Certificate embedded = parsed.getEmbeddedCert(toBeVerified);
        assertNotNull(embedded);
        assertArrayEquals(cert.getEncoded(), embedded.getEncoded());
        assertTrue(new MlDsaCrypto().verify(embedded, null, "", toBeVerified, parsed.getSignature()));
    }

    /**
     * Signatures made with the JDK provider verify under BouncyCastle and vice versa, using keys
     * exchanged only in their standard X.509 SubjectPublicKeyInfo encoding.
     */
    @Test
    public final void testBouncyCastleInterop() throws Exception {
        Provider bc = new BouncyCastleProvider();
        for (String paramSet : PARAMETER_SETS) {
            KeyPair jdkKeys = MlDsaCrypto.generateKeyPair(paramSet);
            byte[] jdkSig = new MlDsaCrypto(jdkKeys).sign(PAYLOAD);
            PublicKey bcPub = KeyFactory.getInstance(paramSet, bc)
                    .generatePublic(new X509EncodedKeySpec(jdkKeys.getPublic().getEncoded()));
            Signature bcVerify = Signature.getInstance(paramSet, bc);
            bcVerify.initVerify(bcPub);
            bcVerify.update(PAYLOAD);
            assertTrue(bcVerify.verify(jdkSig));

            KeyPair bcKeys = KeyPairGenerator.getInstance(paramSet, bc).generateKeyPair();
            Signature bcSign = Signature.getInstance(paramSet, bc);
            bcSign.initSign(bcKeys.getPrivate());
            bcSign.update(PAYLOAD);
            byte[] bcSig = bcSign.sign();
            PublicKey jdkPub = KeyFactory.getInstance("ML-DSA")
                    .generatePublic(new X509EncodedKeySpec(bcKeys.getPublic().getEncoded()));
            assertTrue(new MlDsaCrypto().verify(null, jdkPub, paramSet, PAYLOAD, bcSig));
            assertTrue(new MlDsaCrypto().verify(null, bcKeys.getPublic(), paramSet, PAYLOAD, bcSig));
        }
    }

    private static X509Certificate selfSignedCert(final KeyPair keyPair, final String paramSet)
            throws Exception {
        X500Name name = new X500Name("CN=HIRS ML-DSA Test RIM Signer");
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + ONE_DAY_MS);
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.ONE, notBefore,
                notAfter, name, keyPair.getPublic());
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic()));
        Provider bc = new BouncyCastleProvider();
        // BouncyCastle's content signer needs its own key object; hand it the PKCS #8 encoding
        PrivateKey bcPrivate = KeyFactory.getInstance(paramSet, bc)
                .generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()));
        X509Certificate bcCert = new JcaX509CertificateConverter().setProvider(bc)
                .getCertificate(builder.build(new JcaContentSignerBuilder(paramSet).setProvider(bc)
                        .build(bcPrivate)));
        // Re-parse with the default JDK provider, as a relying party would
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(bcCert.getEncoded()));
    }
}
