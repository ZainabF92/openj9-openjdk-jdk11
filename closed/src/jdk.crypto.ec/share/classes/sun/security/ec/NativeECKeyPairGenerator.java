/*
 * Copyright (c) 2009, 2021, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2022, 2022 All Rights Reserved
 * ===========================================================================
 */

package sun.security.ec;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import sun.security.jca.JCAUtil;
import sun.security.util.ECUtil;
import static sun.security.util.SecurityProviderConstants.DEF_EC_KEY_SIZE;

/**
 * Native EC keypair generator.
 */
public final class NativeECKeyPairGenerator extends KeyPairGeneratorSpi {

    private static final int KEY_SIZE_MIN = 112;
    private static final int KEY_SIZE_MAX = 571;

    /* used to seed the keypair generator */
    private SecureRandom random;

    /* size of the key to generate, KEY_SIZE_MIN <= keySize <= KEY_SIZE_MAX */
    private int keySize;

    /* parameters specified via init, if any */
    private ECParameterSpec params = null;

    /* the type of EC curve */
    private String curve;

    /* the java implementation, initialized if needed */
    private ECKeyPairGenerator javaImplementation;

    /**
     * Constructs a new NativeECKeyPairGenerator.
     */
    public NativeECKeyPairGenerator() {
        // initialize to default in case the app does not call initialize()
        initialize(DEF_EC_KEY_SIZE, null);
    }

    @Override
    public void initialize(int keySize, SecureRandom random) {
        if (keySize < KEY_SIZE_MIN) {
            throw new InvalidParameterException
                ("Key size must be at least " + KEY_SIZE_MIN + " bits");
        }
        if (keySize > KEY_SIZE_MAX) {
            throw new InvalidParameterException
                ("Key size must be at most " + KEY_SIZE_MAX + " bits");
        }
        this.keySize = keySize;
        
        this.params = ECUtil.getECParameterSpec(null, keySize);
        if (this.params == null) {
            throw new InvalidParameterException(
                "No EC parameters available for key size " + keySize + " bits");
        }
        this.random = random;

        this.curve = NativeECUtil.getCurveName(this.params);
        if (NativeECUtil.isCurveSupported(this.curve, this.params)) {
            this.javaImplementation = null;
        } else {
            this.initializeJavaImplementation();
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        ECParameterSpec ecSpec = null;
        if (params instanceof ECParameterSpec) {
            ECParameterSpec ecParams = (ECParameterSpec) params;
            ecSpec = ECUtil.getECParameterSpec(null, ecParams);
            if (ecSpec == null) {
                throw new InvalidAlgorithmParameterException(
                    "Unsupported curve: " + params);
            }
        } else if (params instanceof ECGenParameterSpec) {
            String name = ((ECGenParameterSpec) params).getName();
            ecSpec = ECUtil.getECParameterSpec(null, name);
            if (ecSpec == null) {
                throw new InvalidAlgorithmParameterException(
                    "Unknown curve name: " + name);
            }
        } else {
            throw new InvalidAlgorithmParameterException(
                "ECParameterSpec or ECGenParameterSpec required for EC");
        }
        this.params = ecSpec;

        this.keySize = ecSpec.getCurve().getField().getFieldSize();
        this.random = random;

        this.curve = NativeECUtil.getCurveName(this.params);
        if (NativeECUtil.isCurveSupported(this.curve, this.params)) {
            this.javaImplementation = null;
        } else {
            this.initializeJavaImplementation();
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        if (this.javaImplementation != null) {
            return this.javaImplementation.generateKeyPair();
        }
        long nativePointer = NativeECUtil.encodeGroup(this.params);
        byte[] x = new byte[this.keySize];
        byte[] y = new byte[this.keySize];
        byte[] s = new byte[this.keySize];
        if (nativePointer != -1) {
            if (nativeCrypto.ECGenerateKeyPair(nativePointer, x, x.length, y, y.length, s, s.length) == -1) {
                nativePointer = -1;
            }
        }
        if (nativePointer == -1) {
            if (!NativeECUtil.putCurveIfAbsent(this.curve, Boolean.FALSE, this.curve +
                    " is not supported by OpenSSL, using Java crypto implementation.")) {
                throw new ProviderException("Could not generate key pair");
            }
            this.initializeJavaImplementation();
            return this.javaImplementation.generateKeyPair();
        }
        // TODO: this is a draft of what is needed (I don't think it's a good idea to share the pointer):
        ECPoint w = new ECPoint(new BigInteger(x), new BigInteger(y));
        PublicKey publicKey = new ECPublicKeyImpl(w, this.params);
        publicKey.setNativePointer(nativePointer);
        PrivateKey privateKey = new ECPrivateKeyImpl(new BigInteger(s), this.params);
        privateKey.setNativePointer(nativePointer);
        // TODO: we need to create cleaners for the keys: nativeCrypto.createECKeyCleaner(this, nativePointer);
        // make sure we're freeing everything we need to

        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Initializes the java implementation.
     */
    private void initializeJavaImplementation() {
        try {
            this.javaImplementation = new ECKeyPairGenerator();
            this.javaImplementation.initialize(this.params, this.random);
        } catch (InvalidAlgorithmParameterException e) {
            /* should not happen */
            throw new InternalError(e);
        }
    }
}
