package com.github.unidbg.linux.android.dvm.api;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;

import org.apache.commons.codec.binary.Hex;

import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;

import net.dongliu.apk.parser.bean.CertificateMeta;

public class Signature extends DvmObject<CertificateMeta> {

    public Signature(VM vm, CertificateMeta meta) {
        super(vm.resolveClass("android/content/pm/Signature"), meta);
    }

    public int getHashCode() {
        return Arrays.hashCode(value.getData());
    }

    public byte[] toByteArray() {
        return value.getData();
    }

    public String toCharsString() {
        return Hex.encodeHexString(value.getData());
    }
    
	
	  /**
   * Returns the public key for this signature.
   *
   * @throws CertificateException when Signature isn't a valid X.509
   *             certificate; shouldn't happen.
   * @hide
   */
  public PublicKey getPublicKey() throws CertificateException {
      final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
      final ByteArrayInputStream bais = new ByteArrayInputStream(toByteArray());
      final Certificate cert = certFactory.generateCertificate(bais);
      return cert.getPublicKey();
  }

}
