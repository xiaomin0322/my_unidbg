package com.vivo;

import java.io.File;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.VaList;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.wrapper.DvmBoolean;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;

public class Sign6 extends AbstractJni {

    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    private final Memory memory;

    private Sign6() {
        emulator = AndroidEmulatorBuilder
                //.for32Bit()
        		.for64Bit()
                .setProcessName("com.bbk.appstore")
                .addBackendFactory(new Unicorn2Factory(true))
                .build();
        //emulator.getBackend().registerEmuCountHook(100000);
        emulator.getBackend().registerEmuCountHook(100000);
        emulator.getSyscallHandler().setVerbose(true);
      // emulator.getSyscallHandler().setEnableThreadDispatcher(true);
       emulator.getSyscallHandler().setEnableThreadDispatcher(false);
        
        
        memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        memory.setCallInitFunction(true);

        //vm = emulator.createDalvikVM(new File("unidbg-android/src/test/resources/dy233/dy233.apk"));
        vm = emulator.createDalvikVM(new File("C:\\eclipse-workspace\\unidbg\\unidbg-android\\src\\test\\resources\\vivo\\vivo.apk"));
        //vm = emulator.createDalvikVM();
        vm.setJni(this);
        vm.setVerbose(true);
       // vm.setVerbose(false);
        //DvmClass a = vm.resolveClass("com/vivo/security/jni/SecurityCryptor");
        System.out.println("start>>>>>>>>>>>>>>>>>>>>>>>>>>");
    	File file = new File(
				"C:\\eclipse-workspace\\unidbg\\unidbg-android\\src\\test\\resources\\vivo\\libvivosgmain.so");
		DalvikModule dm = vm.loadLibrary(file, false); // 加载libttEncrypt.so到unicorn虚拟内存，加载成功以后会默认调用init_array等函数
		//DalvikModule dm = vm.loadLibrary("libvivosgmain", true); // 加载libttEncrypt.so到unicorn虚拟内存，加载成功以后会默认调用init_array等函数
        //DalvikModule dm = vm.loadLibrary(new File("C:\\eclipse-workspace\\unidbg\\unidbg-android\\src\\test\\resources\\dy233\\libmetasec_ml.so"), false);
        System.out.println("start2222222222222222222222>>>>>>>>>>>>>>>>>>>>>>>>>>");
        module = dm.getModule();
        dm.callJNI_OnLoad(emulator);
        System.out.println("ok>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        
        Symbol symbol = module.findSymbolByName("Java_com_vivo_security_jni_SecurityCryptor_nativeBase64Decrypt");
        long nativeFuncAddr = symbol.getAddress();
        System.out.println("nativeFuncAddr:"+nativeFuncAddr);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        System.out.println("callObjectMethodV "+ signature);
        switch (signature) {
            case "java/lang/Thread->getStackTrace()[Ljava/lang/StackTraceElement;": {
                DvmObject<?>[] a = {
                        vm.resolveClass("java/lang/StackTraceElement").newObject("dalvik.system.VMStack"),
                        vm.resolveClass("java/lang/StackTraceElement").newObject("java.lang.Thread")
                };
                return new ArrayObject(a);
            }
        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        System.out.println("callStaticObjectMethodV "+ signature);
        switch (signature) {
            case "com/bytedance/mobsec/metasec/ml/MS->b(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;": {
                int a = vaList.getIntArg(0);
                System.out.println("----------------------------");
                System.out.println(a);
                System.out.println("----------------------------");
                if (a == 65539) {
                    return new StringObject(vm,"/data/user/0/com.ss.android.ugc.aweme/files/;o@Y0f");
                } else if (a == 33554433) {
                    return DvmBoolean.valueOf(vm, Boolean.TRUE);
                } else if (a == 33554434) {
                    return DvmBoolean.valueOf(vm, Boolean.TRUE);
                } else if (a == 16777233) {
                    return new StringObject(vm, "23.3.0");
                }
            }
            case "java/lang/Thread->currentThread()Ljava/lang/Thread;": {
                return vm.resolveClass("java/lang/Thread").newObject(Thread.currentThread());
            }
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        System.out.println("callStaticVoidMethodV "+ signature);
        switch (signature) {
            case "com/bytedance/mobsec/metasec/ml/MS->a()V": {
                return;
            }
        }
        super.callStaticVoidMethodV(vm, dvmClass, signature, vaList);
    }

    private String GetSign(String url, String header) {
        Number number = module.callFunction(emulator,
                0x438c0+1, url, header
        );
        System.out.printf("0X%X\n", number.intValue());
        int hash = number.intValue();
        if (this.vm.getObject(hash) == null) {
            System.out.printf("0X%X is null\n", number.intValue());
        }
        UnidbgPointer p = memory.pointer(hash & 0xffffffffL);
        return p.getString(0);
    }

    public static void main(String[] args) {
    	Sign6 sign6 = new Sign6();
    }
}
