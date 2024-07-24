package com.boranget;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;


/**
 * <p>
 * This class is used to encrypt and decrypt data using PGP keys.
 * Encrypted data can be used to call the HSBC Treasury APIs.
 * The response from the HSBC Treasury APIs can be decrypted using the same keys.
 * Keys and the headers used to call the HSBC Treasury APIs are provided by HSBC on the Developer Portal for each project.
 * </p>
 * Created by 44024985 on 04/09/2018.
 * Updated by 45274934 on 28/03/2024.
 */
public class PgpHelper {
    private JcaKeyFingerprintCalculator keyFingerPrintCalculator;

    private Provider bcp;

    public PgpHelper() {
        this.keyFingerPrintCalculator = new JcaKeyFingerprintCalculator();
        this.bcp = new BouncyCastleProvider();
    }

    /**
     * <p>
     * This method reads a public key from an input stream and returns a list of PGP Public Keys.
     * The list of PGP Public Key objects are used as an input for {@link #encryptAndSign(OutputStream, InputStream, PGPPublicKey, PGPPrivateKey)} and {@link #decryptStream(InputStream, OutputStream, List, List)}.
     * </p>
     *
     * @param publicKeyInputStream bank/public key input stream.
     * @return List of PGP Public Keys
     */
    public List<PGPPublicKey> readPublicKey(InputStream publicKeyInputStream) throws IOException, PGPException {

        // public key file is decoded and used to generate a key ring object that stores a list of key rings. These contain the public keys.
        // The fingerPrintCalculator is used to calculate the fingerprint of each key which is needed to verify key authenticity.
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicKeyInputStream),
                this.keyFingerPrintCalculator);

        List<PGPPublicKey> keys = new ArrayList<>();

        pgpPub.getKeyRings().forEachRemaining(keyRing -> keyRing.getPublicKeys().forEachRemaining(keys::add));

        if (keys.isEmpty()) {
            throw new IllegalArgumentException("Can't find encryption key in key ring.");
        }

        return keys;
    }


    /**
     * <p>
     * This method finds a PGP Private key from a PGP secret key ring using a passphrase.
     * </p>
     *
     * @param pgpSecKey Secret Key.
     * @param pass      passphrase to decrypt secret key with.
     * @return PGPPrivate key.
     */
    public PGPPrivateKey findSecretKey(PGPSecretKey pgpSecKey, char[] pass)
            throws PGPException {

        // Extract a private key from a PGPSecretKey object.
        PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder(
                new JcaPGPDigestCalculatorProviderBuilder().setProvider(this.bcp).build()).setProvider(this.bcp).build(pass);

        return pgpSecKey.extractPrivateKey(decryptor);
    }

    /**
     * <p>
     * This method reads a secret key from an input stream and returns a list of PGP Secret Keys.
     * These then need to be extracted to get the private key using the passphrase. This step is carried out by {@link #findSecretKey(PGPSecretKey, char[]) findSecretKey}.
     * </p>
     *
     * @param input private key input stream.
     * @return List of PGP Secret Keys
     */
    public List<PGPSecretKey> readSecretKey(InputStream input) throws IOException, PGPException {

        // Secret key ring collection is generated from the private key file input stream.
        // 创建密钥环
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(input), this.keyFingerPrintCalculator);

        // Loop through key rings, then through keys and add keys found to list.
        List<PGPSecretKey> keys = new ArrayList<>();
        pgpSec.getKeyRings().forEachRemaining(keyRing -> keyRing.getSecretKeys().forEachRemaining(keys::add));
        if (keys.isEmpty()) {
            throw new IllegalArgumentException("Can't find signing key in key ring.");
        } else {
            return keys;
        }
    }


    /**
     * <p>
     * This method encrypts and signs a stream of data using a public key and a private key.
     * The output is a PGP message which as been base64-encoded and contains the signed, encrypted data.
     * </p>
     *
     * @param outf        the output stream
     * @param inputStream the input stream
     * @param encKey      the PGP Public key
     * @param privateKey  the private key
     */
    public void encryptAndSign(OutputStream outf, InputStream inputStream, PGPPublicKey encKey,
                               PGPPrivateKey privateKey) throws IOException {
        OutputStream out = new ArmoredOutputStream(outf);
        OutputStream lOut = null;
        try {
            // Encrypted Data Generator
            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(true)
                            .setSecureRandom(new SecureRandom()).setProvider(this.bcp));
            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider(this.bcp));
            OutputStream encryptedOut = encGen.open(out, new byte[inputStream.available()]);

            // Compressed Data Generator
            PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
            OutputStream compressedData = comData.open(encryptedOut);

            // Signature Generator
            PGPSignatureGenerator sGen = new PGPSignatureGenerator(
                    new JcaPGPContentSignerBuilder(privateKey.getPublicKeyPacket().getAlgorithm(), HashAlgorithmTags.SHA512)
                            .setProvider(this.bcp));
            sGen.init(PGPSignature.BINARY_DOCUMENT, privateKey);

            // Get the user ID from the encryption key, and use this to generate a signed subpacket.
            Iterator it = encKey.getUserIDs();
            if (it.hasNext()) {
                PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
                spGen.setSignerUserID(false, (String) it.next());
                sGen.setHashedSubpackets(spGen.generate());
            }

            // Write the encoded packet to compressed data stream.
            sGen.generateOnePassVersion(false).encode(compressedData); // bOut

            // Create a literal data output stream
            PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
            lOut = lGen.open(compressedData, PGPLiteralData.BINARY, "Sample-Data", new Date(),
                    new byte[inputStream.available()]);

            // Write and sign data.
            byte[] data = IOUtils.toByteArray(inputStream);
            lOut.write(data);
            sGen.update(data);

            lGen.close();

            // Generate signature for compressed data.
            sGen.generate().encode(compressedData);

            comData.close();
            compressedData.close();

            encryptedOut.close();
            encGen.close();

            out.close();
        } catch (PGPException e) {
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        } catch (Exception e) {
            System.err.println(e);
        } finally {
            if (lOut != null) lOut.close();
        }
    }

    /**
     * <p>
     * This method decrypts a stream of data (PGP message) using a list of private keys and a list of public keys.
     * The signature is verified using the public keys.
     * </p>
     *
     * @param in         the input stream
     * @param out        the output stream
     * @param keysIn     the list of private keys
     * @param publicKeys the list of public keys
     */
    public void decryptStream(InputStream in, OutputStream out, List<PGPPrivateKey> keysIn,
                              List<PGPPublicKey> publicKeys) throws Exception {
        PGPObjectFactory pgpF = new PGPObjectFactory(PGPUtil.getDecoderStream(in), this.keyFingerPrintCalculator);
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();


        // Parse first object, which might be a PGP marker packet.
        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        // Find the secret key
        Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
        PGPPublicKeyEncryptedData pbe = null;

        while (it.hasNext()) {
            PGPEncryptedData encryptedData = it.next();
            if (encryptedData instanceof PGPPublicKeyEncryptedData) {
                pbe = (PGPPublicKeyEncryptedData) encryptedData;
            }
        }

        PublicKeyDataDecryptorFactory b;
        InputStream clear = null;
        for (PGPPrivateKey keyIn : keysIn) {
            if (keyIn.getKeyID() == pbe.getKeyID()) {
                b = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(this.bcp).setContentProvider(this.bcp).build(keyIn);
                clear = pbe.getDataStream(b);
                break;
            }
        }
        if (null == clear) {
            throw new PGPKeyValidationException("Invalid public key used for encryption");
        }

        PGPObjectFactory plainFact = new PGPObjectFactory(clear, this.keyFingerPrintCalculator);

        Object message = plainFact.nextObject();

        PGPOnePassSignatureList onePassSignatureList = null;
        PGPSignatureList signatureList = null;
        PGPCompressedData compressedData;
        ByteArrayOutputStream actualOutput = new ByteArrayOutputStream();
        while (message != null) {
            if (message instanceof PGPCompressedData) {
                compressedData = (PGPCompressedData) message;
                plainFact = new PGPObjectFactory(compressedData.getDataStream(), this.keyFingerPrintCalculator);
                message = plainFact.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                // have to read it and keep it somewhere.
                Streams.pipeAll(((PGPLiteralData) message).getInputStream(), actualOutput);
            } else if (message instanceof PGPOnePassSignatureList) {
                onePassSignatureList = (PGPOnePassSignatureList) message;
            } else if (message instanceof PGPSignatureList) {
                signatureList = (PGPSignatureList) message;
            } else {
                throw new PGPException("message unknown message type.");
            }
            message = plainFact.nextObject();
        }
        actualOutput.close();
        byte[] output = actualOutput.toByteArray();
        if (onePassSignatureList == null || signatureList == null) {
            throw new PGPException("Poor PGP. Signatures not found.");
        } else {
            boolean signatureVerified = false;
            for (int i = 0; i < onePassSignatureList.size(); i++) {
                PGPOnePassSignature ops = onePassSignatureList.get(0);
                if (publicKeys != null) {
                    for (PGPPublicKey publicKey : publicKeys) {
                        ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider(this.bcp), publicKey);
                        ops.update(output);
                        PGPSignature signature = signatureList.get(i);
                        if (ops.verify(signature)) {
                            signatureVerified = true;
                        }
                    }
                }
            }
            if (!signatureVerified) {
                throw new SignatureException("Signature verification failed");
            }

        }

        if (pbe.isIntegrityProtected() && !pbe.verify()) {
            throw new PGPDataValidationException("Data is integrity protected but integrity is lost.");
        } else if (publicKeys == null || publicKeys.isEmpty()) {
            throw new SignatureException("Signature not found");
        } else {
            out.write(output);
            out.flush();
            out.close();
        }
    }


}
