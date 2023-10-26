package com.vivo.s1;

import java.io.File;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.cert.CertificateException;

import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.VaList;
import com.github.unidbg.linux.android.dvm.api.Signature;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;

public class TTEncrypt extends AbstractJni {

	private final AndroidEmulator emulator;
	private final VM vm;
	private final Module module;

	private final DvmClass TTEncryptUtils;

	private final boolean logging;

	TTEncrypt(boolean logging) {
		this.logging = logging;

		emulator = AndroidEmulatorBuilder
				// .for32Bit()
				.for64Bit().setProcessName("com.bbk.appstore")
				// .addBackendFactory(new DynarmicFactory(true))
				.addBackendFactory(new Unicorn2Factory(true))
				.build(); // 创建模拟器实例，要模拟32位或者64位，在这里区分
		final Memory memory = emulator.getMemory(); // 模拟器的内存操作接口
		memory.setLibraryResolver(new AndroidResolver(23)); // 设置系统类库解析
		File fileAPK = new File("C:\\eclipse-workspace\\unidbg\\unidbg-android\\src\\test\\resources\\vivo\\vivo.apk");

		vm = emulator.createDalvikVM(fileAPK); // 创建Android虚拟机
		vm.setVerbose(logging); // 设置是否打印Jni调用细节
		vm.setJni(this);
		File file = new File(
				"C:\\eclipse-workspace\\unidbg\\unidbg-android\\src\\test\\resources\\vivo\\libvivosgmain.so");
		DalvikModule dm = vm.loadLibrary(file, false); // 加载libttEncrypt.so到unicorn虚拟内存，加载成功以后会默认调用init_array等函数
		dm.callJNI_OnLoad(emulator); // 手动执行JNI_OnLoad函数
		module = dm.getModule(); // 加载好的libttEncrypt.so对应为一个模块

		TTEncryptUtils = vm.resolveClass("com/vivo/security/jni/SecurityCryptor");

	}

	@Override
	public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
		switch (signature) {
		case "android/app/ActivityThread->getApplication()Landroid/app/Application;":
			return vm.resolveClass("android/app/Application").newObject(signature);
		case "android/content/pm/Signature->getPublicKey()Ljava/security/PublicKey;":
			 if (dvmObject instanceof Signature) {
				 Signature sig = (Signature) dvmObject;
                 System.out.println(sig);
                 try {
                	 PublicKey publicKey = sig.getPublicKey();
                     return vm.resolveClass("java/security/PublicKey").newObject(publicKey);
				} catch (CertificateException e) {
					e.printStackTrace();
				}
             }
			//return vm.resolveClass("java/security/PublicKey").newObject(signature);
		case "java/security/PublicKey->getEncoded()[B":
		  	PublicKey publicKey = (PublicKey)dvmObject.getValue();
			byte[] digest = publicKey.getEncoded();
		    return new ByteArray(vm, digest);
			//return vm.resolveClass("java/security/PublicKey").newObject(signature);
		}
		return super.callObjectMethodV(vm, dvmObject, signature, vaList);
	}

	@Override
	public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
		switch (signature) {
		case "android/util/Base64->encode([BI)[B":
			Integer value = vaList.getIntArg(0);
			ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
			buffer.putInt(value);
			byte[] byteArray = buffer.array();
			int intArg = vaList.getIntArg(1);
			return new ByteArray(vm, Base64.encode(byteArray, intArg));
		}
		return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
	}

	void destroy() {
		IOUtils.close(emulator);
		if (logging) {
			System.out.println("destroy");
		}
	}

	public static void main(String[] args) throws Exception {
		TTEncrypt test = new TTEncrypt(true);

		// byte[] data = test.ttEncrypt();
		// Inspector.inspect(data, "ttEncrypt");
		String str = "c0WD65hYc0uI6M4PTNdfR9E9WNE2cyPnUyh2xlJFh2hDc0uwxe4PTMQ4J2rfcrg06RJ9L5gYtMKPWNQfJ2Pw60uYRl_1cykgcynwx2hYU542xXKgh4uyqq6Cc0hDR01nx5kgTMdmW9KDW9k0W9T2Zl8Cq512x940Wrgnc240WvC0Oy-uTHWnc2CuZ5JSoRZlZqkDK0rDx5hnZ2H2cyPnUyh2xlJFh2hDc0uwxH1nx5kgTqmPJX_DZ5WuRl_9tM-0OMdPOMH0WMk9Wek2Z0gYUyhYUN4u_MduKHZuOMHu_MZuOMduKkZu_MZuONduOM-u_McuKkTuKkTu_MKuKeduONQu_MZuKkTuKM-u_McuO-kuKMHu_MTuONQuONE2Uyh9UyuHcCgXc2gCcN4uW4EuTeEPTeK9OqkDTzk9KqkDTeK1WMQ1JMEDJMJNJMEDTedCTDkDTzk9KqkDTe-4WMdCJMEDJMJNJMEDTMTDWMTuTeEuT4-uTeECTeEDWDkDTzkDKDkDTec1ONEuTeEuT4-uTeECT9HPWDkDTzkDKDkDTe-9W9H9JMEDJMW8JMEDWMKfWNcuTeEuTHTuTeEmONH0JMEDJMW8JMEDT9dPTMQuTeEuTHTuTeEDTMT9JMEDJMW8JMEDTM-0WNTuTeEuTHTuTeEPTekPTvkDTzk9KqkDTeK1W9k1JMEDJMJNJMEDTM-PONHuTeEuT4-uTeE4WMk1WvkDTzkDKDkDTe-9TMQlJMEDJMW8JMEDWM-lT9cuTeEuW4K2c0Wwc2kgWq64c2re6hg4AR8utMKFTv6fL5W4AR8utRUuZXQ2xlW56RJ9L5gYtM-DoeQ2Z5rS6N4DW5KmTMJ2Z9WH65-DT0k1TedCZ9n2TyZmOMEPTeJuT5E1ON_2Z9_n6yk16ME1WeKPWMK9WNWHTMrzW9-46edPJ2gf_2Pn6lTgTMQ0OMEmWME4Wz6Fx0_uxNC0LR6wG0u_M47VhMWmJX8sZR_8cyF56REgTM-fWNQCTN-2L5KgTeTCT9HDWv6wZ5uHtMECZM_zTMEDWeklTyTCZeUeOyk16M_2TyZfW062Wy6uZ9uHWyE9Z0hnTN-f6MHDZ5JzWekPOM_n6eZ9T9u2WeZ26yh0L5Wuhauf6MCfLygY6q64c2re6hgfL0cgZ0gFo2JzLD1sZRhYZ0nuceE2UaJnZ0h3L5KgTN-fJMUNTNKPJMUNTN-uW4TfTeHFTNQ4JMUNTNQDJMUNTN-uW4TfTeH26yhYc0u4AM49oeQ2xygn6rgD6Rr3L5KgWeTCTed9OME9OM-CWNKlW9-0OMdDTNEPTeKDTMc2c0h9c0uwxugS6N4PWeHmTeQPOMH1WMZ1J2Pncl_36yh4Z5usR0uHtME9WMT1TeK2ZR8fU2hDc0uwxe4PTqm1oeEfoeZ0T9H2ZR8fU2hDc0uwx2Ww6ykgWeZ9Oq6uxyrfc0hHUyuF6M4DWME4Tek0J2rYtM-PJX_nc2UuUNCsx0Wnxv6ec94fJX8sZR_3L0h1Rl6uce42U2rS6N4CW0TmT9T1ZeQPO5ElT5E9Zene6eJHWMcPT2-0T9WuTMKPZM8z6MdDONEfWMJn656uTMd96NJe6MEmZeTCTNuuJX8sZR_8cyF56RJOZ5CutM-YTMQYWvmCTN-2c94DJMUNTMdmWN-1W9E9Wv6sZRW4R0_uUyrSxrgVclKgWv6CtMQPT2TPZ0_uW9ECZ9re6yJn6MQ9Te-fTNQfTNQfTNQfTNQfTv6nUe49Tv6Cc0hDR0uHtMKDW2T0T5-fo5WzWNHFWyruTv41TN-moMUz6ed0TMcDT9cf6q6fxyr462gDxhgSx26wthWWWNTCTv6F6XEgU2u0xD6Sx5hStq6zU5us6rgYU5Cz6REgk-KDTMQ0Kug8R9-YTMEYTv6fZR_eLrg9URQgTz6CLhgFx0_utMQ2LX6PRl_1cykgTQ&";
		str = "c0WD65hYc0uI6M4PTNdfR9E9WNE2cyPnUyh2xlJFh2hDc0uwxe4PTMQ4J2rfcrg06RJ9L5gYtMKPWNQfJ2Pw60uYRl_1cykgcynwx2hYU542xXKgh4uyqq6Cc0hDR01nx5kgTMdmW9KfOMklTek2Zl8Cq512x940Wrgnc240WvC0Oy-uTHWnc2CuZ5JSoRZlZqkDK0rDx5hnZ2H2cyPnUyh2xlJFh2hDc0uwxH1nx5kgTqmPJX_DZ5WuRl_9tM-0OMdDTNTCTMK1ON-2Z0gYUyhYUN4u_MkuOMTuONdu_MkuOMTuONdu_MkuOMTuONdu_MkuOMTuONdu_kZuKHTuO-Tu_McuOkEuKedu_MkuKHKuOMTu_MkuO-ZuKkZu_MKuKHEuKMk2Uyh9UyuHcCgXc2gCcN4uW4EuTeEPTeK9OqkDTzk9KqkDTeK1WMQ1JMEDJMJNJMEDTedCTDkDTzk9KqkDTe-4WMdCJMEDJMJNJMEDTMTDWMTuTeEuT4-uTeECTeEDWDkDTzkDKDkDTec1ONEuTeEuT4-uTeECT9HPWDkDTzkDKDkDTe-9W9H9JMEDJMW8JMEDWMKfWNcuTeEuTHTuTeEmONH0JMEDJMW8JMEDT9dPTMQuTeEuTHTuTeEDTMT9JMEDJMW8JMEDTM-0WNTuTeEuTHTuTeEPTekPTvkDTzk9KqkDTeK1W9k1JMEDJMJNJMEDTM-PONHuTeEuT4-uTeE4WMk1WvkDTzkDKDkDTe-9TMQlJMEDJMW8JMEDWM-lT9cuTeEuW4K2c0Wwc2kgWq64c2re6hg4AR8utMKFTv6fL5W4AR8utRUuZXQ2xlW56RJ9L5gYtM-DoeQ2Z5rS6N4DW5KmTMJ2Z9WH65-DT0k1TedCZ9n2TyZmOMEPTeJuT5E1ON_2Z9_n6yk16ME1WeKPWMK9WNWHTMrzW9-46edPJ2gf_2Pn6lTgTMQ0OMEmWME4Wz6Fx0_uxNC0LR6wG0u_M47VhMWmJX8sZR_8cyF56REgTM-fWNQCTN-2L5KgTeTCT9HDWv6wZ5uHtMECZM_zTMEDWeklTyTCZeUeOyk16M_2TyZfW062Wy6uZ9uHWyE9Z0hnTN-f6MHDZ5JzWekPOM_n6eZ9T9u2WeZ26yh0L5Wuhauf6MCfLygY6q64c2re6hgfL0cgZ0gFo2JzLD1sZRhYZ0nuceE2UaJnZ0h3L5KgTN-fJMUNTNKPJMUNTN-uW4TfTeHFTNQ4JMUNTNQDJMUNTN-uW4TfTeH26yhYc0u4AM49oeQ2xygn6rgD6Rr3L5KgW9kPWMT1TMZ4TMkfWN-lW9-0OMdDTNT0TeclTNd2c0h9c0uwxugS6N4PWeHmTeQ9WMT1T9ZfJ2Pncl_36yh4Z5usR0uHtME9WMT1TeK2ZR8fU2hDc0uwxe4PTqm1oeEfoeZ0T9H2ZR8fU2hDc0uwx2Ww6ykgWeZ9Oq6uxyrfc0hHUyuF6M4PW9TlT9k2Z5mgTM-2UyrD60h4t5PwZ0rsJ2W9tMQ2cyPnUrgV6Ru3U2hDtq60Z5uHtMklZ9d9T9uzTN-1ZecPZeWzOyW2T2KCW9-DZMZ9T0kPWNrnTyJuONEmTeQCT2ru62kPONWHT2WuTenzT9kfO5k2cyPnU-rfLC6ucH1nx5kgTqmPTvm4oekfTq69tMEuW4TmWedDTMKDWNE2xyr9UrgH6R_nL5P3LlW4tMK2UM4fTMJeT5WH6McDW5TPZ0_zZ5kfT9EPTNQfTNQfTNQfTNQfTNQ2ZRZgT9Q2URWucugS6N4PW06eW0Z96z44WMJeoMKPZeKFZ5ZfZD40Z5Wu6eU2T9ZDONE2cyPnUy6wc2C3L512x9CMMMK9WMQ2x56DtR6SU272L5CuLM42ZXhSxy_3xXhFZ2hDth8-Te-fWHJ3Kh7Poe-DoeQ2cyr4Z0n3clhftME2U5u3x5gH6M4fJ2S0chg4AR8utMQ&";
		test.callInit();
		test.nativeCheckSignatures();
		// test.nativeGetRsaPrivateKey();
		// String ttEncrypt = test.ttdecrypt(str);
		String ttEncrypt = test.ttEncrypt("asdf");
		System.out.println("解妈：" + ttEncrypt);
		test.destroy();
	}

	public void callInit() {
		boolean callStaticJniMethodBoolean = TTEncryptUtils.callStaticJniMethodBoolean(emulator,
				"nativeSecurityInit()Z");
		System.out.println("callInit返回值:" + callStaticJniMethodBoolean);
	}
	
	public void nativeCheckSignatures() {
		boolean callStaticJniMethodBoolean = TTEncryptUtils.callStaticJniMethodBoolean(emulator,
				"nativeCheckSignatures()Z");
		System.out.println("nativeCheckSignatures返回值:" + callStaticJniMethodBoolean);
	}
	
	

	public String nativeGetRsaPrivateKey() {
		DvmObject<?> callStaticJniMethodObject = TTEncryptUtils.callStaticJniMethodObject(emulator,
				"nativeGetRsaPrivateKey()[B");
		System.out.println("callInit返回值:" + callStaticJniMethodObject);
		return new String(((ByteArray) callStaticJniMethodObject).getValue());
	}

	public String ttdecrypt(String str) throws Exception {
		// 0x1f818
//    	ByteArray callStaticJniMethodObject = TTEncryptUtils.callStaticJniMethodObject(emulator, "nativeBase64Decrypt([B)[B", new ByteArray(vm, str.getBytes("utf-8")));

		Object callStaticJniMethodObject = TTEncryptUtils.callStaticJniMethodObject(emulator,
				"nativeBase64Decrypt([B)[B", str.getBytes("utf-8"));

		Class<? extends DvmClass> class1 = TTEncryptUtils.getClass();
		// System.out.println("class1:"+class1);

		Method[] methods = class1.getMethods();
		for (Method m : methods) {
			// System.out.println("Method::::::"+m.getName());
		}

		System.out.println("byte[]>>>>>>>>>" + callStaticJniMethodObject);
		// Symbol symbol =
		// module.findSymbolByName("Java_com_vivo_security_jni_SecurityCryptor_nativeBase64Decrypt");
		// long nativeFuncAddr = symbol.getAddress();
		// System.out.println("nativeFuncAddr===============:"+nativeFuncAddr);
		return new String(((ByteArray) callStaticJniMethodObject).getValue());
	}

	public String ttEncrypt(String str) throws Exception {
		
		//DvmObject<?> callStaticJniMethodObject = TTEncryptUtils.newObject(null).callJniMethodObject(emulator,"nativeBase64Encrypt([B)[B", new ByteArray(vm, str.getBytes("utf-8")));
		
		ByteArray callStaticJniMethodObject = TTEncryptUtils.callStaticJniMethodObject(emulator,"nativeBase64Encrypt([B)[B", new ByteArray(vm, str.getBytes("utf-8")));
		// Object callStaticJniMethodObject = TTEncryptUtils.callStaticJniMethodObject(emulator,
		// "nativeBase64Encrypt([B)[B", str.getBytes("utf-8"));
		System.out.println("byte[]>>>>>>>>>" + callStaticJniMethodObject);
		return new String(((ByteArray) callStaticJniMethodObject).getValue());
		
		
		
	}

}
