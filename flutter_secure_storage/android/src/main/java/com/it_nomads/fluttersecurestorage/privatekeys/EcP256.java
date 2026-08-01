package com.it_nomads.fluttersecurestorage.privatekeys;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.AlgorithmParameters;
import java.security.interfaces.ECPrivateKey;

/**
 * Minimal P-256 public-key derivation for software key import (no BouncyCastle).
 */
final class EcP256 {
    private EcP256() {}

    static PublicKey publicFromPrivate(ECPrivateKey privateKey) throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec ecSpec = parameters.getParameterSpec(ECParameterSpec.class);
        ECPoint generator = ecSpec.getGenerator();
        BigInteger d = privateKey.getS();
        ECPoint publicPoint = scalarMultiply(generator, d, ecSpec.getCurve());
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(publicPoint, ecSpec));
    }

    private static ECPoint scalarMultiply(ECPoint point, BigInteger k, EllipticCurve curve) {
        ECPoint result = ECPoint.POINT_INFINITY;
        ECPoint addend = point;
        BigInteger scalar = k;
        while (scalar.signum() > 0) {
            if (scalar.testBit(0)) {
                result = addPoints(result, addend, curve);
            }
            addend = addPoints(addend, addend, curve);
            scalar = scalar.shiftRight(1);
        }
        return result;
    }

    private static ECPoint addPoints(ECPoint a, ECPoint b, EllipticCurve curve) {
        if (a.equals(ECPoint.POINT_INFINITY)) {
            return b;
        }
        if (b.equals(ECPoint.POINT_INFINITY)) {
            return a;
        }
        BigInteger p = ((ECFieldFp) curve.getField()).getP();
        BigInteger x1 = a.getAffineX();
        BigInteger y1 = a.getAffineY();
        BigInteger x2 = b.getAffineX();
        BigInteger y2 = b.getAffineY();

        if (x1.equals(x2) && y1.add(y2).mod(p).equals(BigInteger.ZERO)) {
            return ECPoint.POINT_INFINITY;
        }

        BigInteger lambda;
        if (x1.equals(x2) && y1.equals(y2)) {
            BigInteger numerator = x1.modPow(BigInteger.valueOf(2), p)
                    .multiply(BigInteger.valueOf(3))
                    .add(curve.getA())
                    .mod(p);
            BigInteger denominator = y1.shiftLeft(1).modInverse(p);
            lambda = numerator.multiply(denominator).mod(p);
        } else {
            lambda = y2.subtract(y1).multiply(x2.subtract(x1).modInverse(p)).mod(p);
        }

        BigInteger x3 = lambda.modPow(BigInteger.valueOf(2), p).subtract(x1).subtract(x2).mod(p);
        BigInteger y3 = lambda.multiply(x1.subtract(x3)).subtract(y1).mod(p);
        return new ECPoint(x3, y3);
    }
}
