package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.pqc.jcajce.interfaces.LMSPrivateKey;
import org.bouncycastle.pqc.jcajce.spec.LMSHSSKeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.LMSKeyGenParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;

/**
 * LMS is now promoted to the BC provider.
 */
public class LMSTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testKeyPairGenerators()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("LMS", "BC");

        KeyPair kp = kpGen.generateKeyPair();

        trySigning(kp);

        kpGen.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1));

        kp = kpGen.generateKeyPair();

        trySigning(kp);

        kpGen.initialize(new LMSHSSKeyGenParameterSpec(
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1),
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1)
            ), new SecureRandom());

        kp = kpGen.generateKeyPair();

        trySigning(kp);
    }

    private void trySigning(KeyPair keyPair)
        throws Exception
    {
        byte[] msg = Strings.toByteArray("Hello, world!");
        Signature signer = Signature.getInstance("LMS", "BC");

        signer.initSign(keyPair.getPrivate(), new SecureRandom());

        signer.update(msg);

        byte[] sig = signer.sign();

        signer.initVerify(keyPair.getPublic());

        signer.update(msg);

        assertTrue(signer.verify(sig));
    }

    public void testKeyFactoryLMSKey()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("LMS", "BC");

        kpGen.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1));

        KeyPair kp = kpGen.generateKeyPair();

        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());

        KeyFactory kFact = KeyFactory.getInstance("LMS", "BC");

        PublicKey pub1 = kFact.generatePublic(x509KeySpec);

        assertEquals(kp.getPublic(), pub1);

        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());

        PrivateKey priv1 = kFact.generatePrivate(pkcs8KeySpec);

        assertEquals(kp.getPrivate(), priv1);

        kFact = KeyFactory.getInstance(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig.getId(), "BC");

        pub1 = kFact.generatePublic(x509KeySpec);

        assertEquals(kp.getPublic(), pub1);
    }

    public void testPublicKeyEncodingLength()
        throws Exception
    {
        KeyPairGenerator kpGen1 = KeyPairGenerator.getInstance("LMS", "BC");

        kpGen1.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1));

        KeyPair kp1 = kpGen1.generateKeyPair();

        KeyPairGenerator kpGen2 = KeyPairGenerator.getInstance("LMS", "BC");

        kpGen2.initialize(new LMSHSSKeyGenParameterSpec(
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1),
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1)
            ), new SecureRandom());

        KeyPair kp2 = kpGen2.generateKeyPair();

        assertEquals(kp1.getPublic().getEncoded().length, kp2.getPublic().getEncoded().length);
    }

    public void testKeyFactoryHSSKey()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("LMS", "BC");

        kpGen.initialize(new LMSHSSKeyGenParameterSpec(
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1),
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1)
            ), new SecureRandom());

        KeyPair kp = kpGen.generateKeyPair();

        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());

        KeyFactory kFact = KeyFactory.getInstance("LMS", "BC");

        PublicKey pub1 = kFact.generatePublic(x509KeySpec);

        assertEquals(kp.getPublic(), pub1);

        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());
        
        PrivateKey priv1 = kFact.generatePrivate(pkcs8KeySpec);

        assertEquals(kp.getPrivate(), priv1);

        kFact = KeyFactory.getInstance(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig.getId(), "BC");

        pub1 = kFact.generatePublic(x509KeySpec);

        assertEquals(kp.getPublic(), pub1);
    }

    /**
     * An X.509 / PKCS#8 encoded HSS key carrying an out of range level count L must be
     * rejected by the key factory, otherwise a matching signature (Nspk = L - 1) drives an
     * allocation of L - 1 signed public key slots before any data is read.
     */
    public void testKeyFactoryHSSKeyExcessiveLevelCountRejected()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("LMS", "BC");

        kpGen.initialize(new LMSHSSKeyGenParameterSpec(
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1),
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1)
            ), new SecureRandom());

        KeyPair kp = kpGen.generateKeyPair();

        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        byte[] hssPub = ASN1OctetString.getInstance(pubInfo.parsePublicKey()).getOctets();
        Pack.intToBigEndian(Integer.MAX_VALUE, hssPub, 0);

        KeyFactory kFact = KeyFactory.getInstance("LMS", "BC");

        SubjectPublicKeyInfo badPubInfo = new SubjectPublicKeyInfo(pubInfo.getAlgorithm(), new DEROctetString(hssPub));
        try
        {
            kFact.generatePublic(new X509EncodedKeySpec(badPubInfo.getEncoded()));
            fail("HSS public key with L = " + Integer.MAX_VALUE + " accepted");
        }
        catch (InvalidKeySpecException e)
        {
            assertEquals("L value of HSS public key out of range: " + Integer.MAX_VALUE, e.getCause().getMessage());
        }

        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
        PrivateKeyInfo badPrivInfo = new PrivateKeyInfo(privInfo.getPrivateKeyAlgorithm(),
            privInfo.parsePrivateKey(), privInfo.getAttributes(), hssPub);
        try
        {
            kFact.generatePrivate(new PKCS8EncodedKeySpec(badPrivInfo.getEncoded()));
            fail("HSS private key with public key L = " + Integer.MAX_VALUE + " accepted");
        }
        catch (InvalidKeySpecException e)
        {
            assertEquals("L value of HSS public key out of range: " + Integer.MAX_VALUE, e.getCause().getMessage());
        }
    }

    public void testKeyGenAndSignTwoSigsWithShardHSS()
        throws Exception
    {
        byte[] msg1 = Strings.toByteArray("Hello, world!");
        byte[] msg2 = Strings.toByteArray("Now is the time");

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("LMS", "BC");

        kpGen.initialize(
            new LMSHSSKeyGenParameterSpec(
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4)), new SecureRandom());

        KeyPair kp = kpGen.generateKeyPair();

        LMSPrivateKey privKey = ((LMSPrivateKey)kp.getPrivate()).extractKeyShard(2);

        assertEquals(2,  ((LMSPrivateKey)kp.getPrivate()).getIndex());

        assertEquals(2, privKey.getUsagesRemaining());
        assertEquals(0, privKey.getIndex());

        Signature signer = Signature.getInstance("LMS", "BC");

        signer.initSign(privKey);

        signer.update(msg1);

        byte[] sig1 = signer.sign();

        assertEquals(1, privKey.getIndex());

        signer.initVerify(kp.getPublic());

        signer.update(msg1);

        assertTrue(signer.verify(sig1));

        signer.initSign(privKey);

        signer.update(msg2);

        byte[] sig2 = signer.sign();

        assertEquals(0, privKey.getUsagesRemaining());

        try
        {
            signer.update(msg2);

            fail("no exception");
        }
        catch (SignatureException e)
        {
            assertEquals("hss private key shard is exhausted", e.getMessage());
        }

        signer = Signature.getInstance("LMS", "BC");

        signer.initVerify(kp.getPublic());

        signer.update(msg2);

        assertTrue(signer.verify(sig2));
  
        try
        {
            signer.initSign(privKey);
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("private key exhausted", e.getMessage());
        }

        assertEquals(2,  ((LMSPrivateKey)kp.getPrivate()).getIndex());

        signer.initSign(kp.getPrivate());

        signer.update(msg1);

        byte[] sig = signer.sign();
        
        signer.initVerify(kp.getPublic());

        signer.update(msg1);

        assertTrue(signer.verify(sig));
        assertFalse(Arrays.areEqual(sig1, sig));
        assertEquals(3,  ((LMSPrivateKey)kp.getPrivate()).getIndex());
    }
}
