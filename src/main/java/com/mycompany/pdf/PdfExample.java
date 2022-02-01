package com.mycompany.pdf;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.util.Base64;

public class PdfExample {
    
    private static final String IN_PDF  = "sample.pdf";
    private static final String OUT_SIGNED_PDF = "sample-signed.pdf";
    private static final String OUT_SIGNED_LTV_PDF = "sample-signed-ltv.pdf";
    private static final String PASSWORD = "";

    private static final InputStream CERTIFICATE_64
            = new ByteArrayInputStream(Base64.getDecoder().decode("** SIGNATURE IN BASE64"));
    
    static {
        BouncyCastleProvider bcp = new BouncyCastleProvider();
        Security.addProvider(bcp);
    }

    public static void main(String[] args) throws Exception {

        InputStream inputFile = new FileInputStream(IN_PDF);
        try (OutputStream outputSignedFile = new FileOutputStream(OUT_SIGNED_PDF)) {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(CERTIFICATE_64, PASSWORD.toCharArray());
            String alias = ks.aliases().nextElement();
            PrivateKey pk = (PrivateKey) ks.getKey(alias, "".toCharArray());
            Certificate[] chain = ks.getCertificateChain(alias);
            
            applySignature(inputFile, outputSignedFile,
                    chain,
                    pk,
                    DigestAlgorithms.SHA1,
                    BouncyCastleProvider.PROVIDER_NAME,
                    PdfSigner.CryptoStandard.CADES,
                    "Signature", "Ghent");
        }

        PdfReader pdfSigned = new PdfReader(new FileInputStream(OUT_SIGNED_PDF));
        PdfDocument pdf = new PdfDocument(pdfSigned, new PdfWriter(OUT_SIGNED_LTV_PDF), new StampingProperties().preserveEncryption().useAppendMode());

        AdobeLtvEnabling adobeLtvEnabling = new AdobeLtvEnabling(pdf);
        adobeLtvEnabling.enable();
    }
    
    private static void applySignature(InputStream src,
            OutputStream dest,
            Certificate[] chain,
            PrivateKey pk,
            String digestAlgorithm,
            String provider,
            PdfSigner.CryptoStandard subfilter,
            String reason,
            String location)
            throws GeneralSecurityException, IOException {

        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, dest, true);

        PdfSignatureAppearance appearance = signer.getSignatureAppearance()
                .setReason(reason)
                .setLocation(location) // TODO
                .setReuseAppearance(false);
        Rectangle rect = new Rectangle(0, 0, 0, 0);
        appearance.setPageRect(rect).setPageNumber(1);
        signer.setFieldName("Signature1");
        IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();
        signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);
    }    

}
