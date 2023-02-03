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

import java.security.spec.ECParameterSpec;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import jdk.crypto.jniprovider.NativeCrypto;

/**
 * Utility methods for the native EC implementation.
 */
public static class NativeECUtil {

    private static final NativeCrypto nativeCrypto = NativeCrypto.getNativeCrypto();
    private static final boolean nativeCryptTrace = NativeCrypto.isTraceEnabled();

    /* false if OPENSSL_NO_EC2M is defined, true otherwise */
    private static final boolean nativeGF2m = nativeCrypto.ECNativeGF2m();

    /* stores whether a curve is supported by OpenSSL (true) or not (false) */
    private static final Map<String, Boolean> curveSupported = new ConcurrentHashMap<>();

    /**
     * Checks whether the given EC curve is not supported by OpenSSL.
     * @param curve the EC curve type
     * @param params the parameters of the EC curve
     * @return false if the curve is not supported, true otherwise.
     */
    static boolean isCurveSupported(String curve, ECParameterSpec params) {
        if ((!nativeGF2m) && (params.getCurve().getField() instanceof ECFieldF2m)) {
            NativeECUtil.putCurveIfAbsent("EC2m", Boolean.FALSE, 
                    "EC2m is not supported by OpenSSL, using Java crypto implementation.");
            return false;
        } else {
            return curveSupported.getOrDefault(curve, Boolean.TRUE).booleanValue();
        }
    }

    /**
     * Records whether the specified EC curve is supported by OpenSSL or not,
     * if the curve is not already associated with a value.
     * @param curve the EC curve type
     * @param supported true if the curve is supported by OpenSSL, false otherwise
     * @param trace the message to print on success, if the native crypto trace is enabled
     * @return true on success (i.e. the curve was not associated with a value), false otherwise
     */
    static boolean putCurveIfAbsent(String curve, Boolean supported, String trace) {
        boolean absent = (curveSupported.putIfAbsent(curve, supported) == null);
        /* only print the first time a curve is used */
        if (absent && nativeCryptTrace) {
            System.err.println(trace);
        }
        return absent;
    }

    /**
     * Returns the EC curve type.
     * @param params the parameters of the EC curve
     * @return the name or OID of the EC curve
     */
    static String getCurveName(ECParameterSpec params) {
        String curveName;
        if (params instanceof NamedCurve) {
            curveName = ((NamedCurve) params).getName();
        } else {
            /* use the OID */
            try {
                AlgorithmParameters algParams = AlgorithmParameters.getInstance("EC");
                algParams.init(params);
                curveName = algParams.getParameterSpec(ECGenParameterSpec.class).getName();
            } catch (InvalidParameterSpecException | NoSuchAlgorithmException e) {
                /* should not happen */
                throw new InternalError(e);
            }
        }
        return curveName;
    }

    /**
     * Returns the native EC public key context pointer.
     * @param params the parameters of the EC curve
     * @return the native EC key context pointer or -1 on error
     */
    static long encodeGroup(ECParameterSpec params) {
        ECPoint generator = params.getGenerator();
        EllipticCurve curve = params.getCurve();
        ECField field = curve.getField();
        byte[] a = curve.getA().toByteArray();
        byte[] b = curve.getB().toByteArray();
        byte[] gx = generator.getAffineX().toByteArray();
        byte[] gy = generator.getAffineY().toByteArray();
        byte[] n = params.getOrder().toByteArray();
        byte[] h = BigInteger.valueOf(params.getCofactor()).toByteArray();
        long nativePointer;
        if (field instanceof ECFieldFp) {
            byte[] p = ((ECFieldFp)field).getP().toByteArray();
            nativePointer = nativeCrypto.ECEncodeGFp(a, a.length, b, b.length, p, p.length, gx, gx.length, gy, gy.length, n, n.length, h, h.length);
        } else if (field instanceof ECFieldF2m) {
            byte[] p = ((ECFieldF2m)field).getReductionPolynomial().toByteArray();
            nativePointer = nativeCrypto.ECEncodeGF2m(a, a.length, b, b.length, p, p.length, gx, gx.length, gy, gy.length, n, n.length, h, h.length);
        } else {
            nativePointer = -1;
        }
        return nativePointer;
    }
}
