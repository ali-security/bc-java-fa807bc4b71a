package org.bouncycastle.pkix.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * CVE-2026-103617: which CRL the bcprov org.bouncycastle.x509.PKIXCertPathReviewer lets decide a
 * certificate's status, checked against CertPathValidator("PKIX", "BC"). Only a complete CRL decides:
 * a delta CRL lists only the changes since its base (RFC 5280 sec. 5.2.4), so taking a current delta
 * as the answer reported a certificate revoked on an expired base as not revoked.
 * <p>
 * Ported from upstream b7172ae1, restricted to the delta-CRL cases and to the reviewer copy that
 * ships in bcprov (the org.bouncycastle.pkix.jcajce copy ships in bcpkix).
 */
public class PKIXCertPathReviewerCrlSelectionTest
    extends TestCase
{
    private static final long HOUR = 60 * 60 * 1000L;
    private static final long DAY = 24 * HOUR;

    private static final BigInteger EE_SERIAL = BigInteger.valueOf(7);

    private Date validationDate;

    private X500Name caDn;
    private X509Certificate caCert;
    private X509Certificate eeCert;
    private ContentSigner caSigner;

    public void setUp()
        throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        validationDate = new Date(System.currentTimeMillis() - 10 * DAY);

        KeyPair caKp = generateKeyPair();
        KeyPair eeKp = generateKeyPair();

        caDn = new X500Name("CN=CRL Selection Test CA");
        X500Name eeDn = new X500Name("CN=CRL Selection Test EE");

        caSigner = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(caKp.getPrivate());

        JcaX509v3CertificateBuilder caBldr = new JcaX509v3CertificateBuilder(
            caDn, BigInteger.valueOf(1), at(-100 * DAY), at(100 * DAY), caDn, caKp.getPublic());

        caBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        caBldr.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        caCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(caBldr.build(caSigner));

        JcaX509v3CertificateBuilder eeBldr = new JcaX509v3CertificateBuilder(
            caDn, EE_SERIAL, at(-50 * DAY), at(50 * DAY), eeDn, eeKp.getPublic());

        eeBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        eeBldr.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));

        eeCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(eeBldr.build(caSigner));
    }

    /**
     * The base CRL revoking the certificate has expired and a current delta against it, listing no
     * changes, is all that is current: the delta is not an answer on its own.
     */
    public void testExpiredBaseWithCurrentDeltaIsNotProofOfNonRevocation()
        throws Exception
    {
        X509CRL expiredBase = createCRL(10, null, -3 * DAY, -DAY, true);
        X509CRL delta = createCRL(11, BigInteger.valueOf(10), -HOUR, DAY, false);

        X509CRL[] crls = new X509CRL[]{ expiredBase, delta };

        // with no current complete CRL the reviewers fall back to reading the expired base, and so report its revocation
        assertEngineRejects(crls);
        assertReviewersReject(crls, "CertPathReviewer.certRevoked");
    }

    /**
     * Two deltas against a base the reviewer is not given, the earlier one expired: neither decides.
     */
    public void testDeltasWithoutBaseAreNotProofOfNonRevocation()
        throws Exception
    {
        X509CRL expiredDelta = createCRL(11, BigInteger.valueOf(10), -2 * DAY, -HOUR, false);
        X509CRL delta = createCRL(12, BigInteger.valueOf(10), -HOUR, DAY, false);

        X509CRL[] crls = new X509CRL[]{ expiredDelta, delta };

        assertEngineRejects(crls);
        assertReviewersReject(crls, "CertPathReviewer.noValidCrlFound");
    }

    /**
     * Compatibility: with a current complete CRL present, a current delta beside it changes nothing -
     * the revocation on the complete CRL is reported, and an unrevoked certificate stays valid.
     */
    public void testCurrentBaseDecidesBesideDelta()
        throws Exception
    {
        X509CRL delta = createCRL(11, BigInteger.valueOf(10), -HOUR, DAY, false);

        X509CRL[] revoking = new X509CRL[]{ delta, createCRL(10, null, -2 * DAY, 2 * DAY, true) };

        assertEngineRejects(revoking);
        assertReviewersReject(revoking, "CertPathReviewer.certRevoked");

        X509CRL[] clean = new X509CRL[]{ delta, createCRL(10, null, -2 * DAY, 2 * DAY, false) };

        CertPathValidator.getInstance("PKIX", "BC").validate(certPath(), params(clean));
        assertTrue("legacy reviewer rejected a current complete CRL", legacyReview(clean).isValidCertPath());
    }

    private void assertReviewersReject(X509CRL[] crls, String errorId)
        throws Exception
    {
        org.bouncycastle.x509.PKIXCertPathReviewer legacy = legacyReview(crls);
        assertFalse("legacy reviewer accepted the path", legacy.isValidCertPath());
        assertTrue("legacy reviewer did not report " + errorId, hasId(legacy.getErrors(0), errorId));
        assertFalse("legacy reviewer reported the certificate as not revoked",
            hasId(legacy.getNotifications(0), "CertPathReviewer.notRevoked"));
    }

    private void assertEngineRejects(X509CRL[] crls)
        throws Exception
    {
        try
        {
            CertPathValidator.getInstance("PKIX", "BC").validate(certPath(), params(crls));
            fail("CertPathValidator accepted the path");
        }
        catch (CertPathValidatorException e)
        {
            // expected
        }
    }

    private org.bouncycastle.x509.PKIXCertPathReviewer legacyReview(X509CRL[] crls)
        throws Exception
    {
        org.bouncycastle.x509.PKIXCertPathReviewer reviewer = new org.bouncycastle.x509.PKIXCertPathReviewer();

        reviewer.init(certPath(), params(crls));

        return reviewer;
    }

    private CertPath certPath()
        throws Exception
    {
        return CertificateFactory.getInstance("X.509", "BC").generateCertPath(Collections.singletonList(eeCert));
    }

    private PKIXParameters params(X509CRL[] crls)
        throws Exception
    {
        List store = new ArrayList();

        store.add(caCert);
        store.add(eeCert);
        for (int i = 0; i != crls.length; i++)
        {
            store.add(crls[i]);
        }

        PKIXParameters params = new PKIXParameters(Collections.singleton(new TrustAnchor(caCert, null)));

        params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(store), "BC"));
        params.setRevocationEnabled(true);
        params.setDate(validationDate);

        return params;
    }

    private X509CRL createCRL(int number, BigInteger baseNumber, long thisUpdate, long nextUpdate,
                              boolean revokeEE)
        throws Exception
    {
        X509v2CRLBuilder crlBldr = new X509v2CRLBuilder(caDn, at(thisUpdate));

        crlBldr.setNextUpdate(at(nextUpdate));
        crlBldr.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(number)));

        if (baseNumber != null)
        {
            crlBldr.addExtension(Extension.deltaCRLIndicator, true, new CRLNumber(baseNumber));
        }
        if (revokeEE)
        {
            crlBldr.addCRLEntry(EE_SERIAL, at(-5 * DAY), CRLReason.keyCompromise);
        }

        return new JcaX509CRLConverter().setProvider("BC").getCRL(crlBldr.build(caSigner));
    }

    private Date at(long offset)
    {
        return new Date(validationDate.getTime() + offset);
    }

    private static KeyPair generateKeyPair()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");

        kpg.initialize(256);

        return kpg.generateKeyPair();
    }

    private static boolean hasId(List bundles, String id)
    {
        for (int i = 0; i != bundles.size(); i++)
        {
            if (id.equals(((org.bouncycastle.i18n.ErrorBundle)bundles.get(i)).getId()))
            {
                return true;
            }
        }

        return false;
    }
}
